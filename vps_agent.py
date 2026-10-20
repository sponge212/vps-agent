#!/usr/bin/env python3
"""
VPS Agent — lightweight HTTP agent for remote server management.

Runs as a systemd service. Listens on an auto-selected port (8765-8780).
Authenticates every request with a Bearer token stored in /opt/vps-agent/token.

Endpoints (all require token except /health and /register-if-not-configured):
    GET  /health                       -> status, uptime, port
    POST /register      {token}        -> set initial token
    POST /update-token  {new_token}    -> rotate token
    GET  /info                         -> hostname, OS, uptime, mem, disk, tmux, services
    GET  /tmux                         -> tmux sessions
    POST /service/<name>/<action>      -> systemctl start/stop/restart/status
    GET  /logs/<service>?lines=N      -> journalctl tail
    POST /restart                      -> reboot server (3s delay)
"""
import os
import re
import json
import socket
import subprocess
from collections import defaultdict
from time import time

from flask import Flask, request, jsonify

app = Flask(__name__)

INSTALL_DIR = '/opt/vps-agent'
TOKEN_FILE = os.path.join(INSTALL_DIR, 'token')
PORT_FILE = os.path.join(INSTALL_DIR, 'port')

# Rate limiting: 10 requests / 60s per IP (slows down brute-force scanners)
_rate = defaultdict(list)


def rate_ok(ip, max_req=10, window=60):
    now = time()
    _rate[ip] = [t for t in _rate[ip] if now - t < window]
    if len(_rate[ip]) >= max_req:
        return False
    _rate[ip].append(now)
    return True


INFO_CMD = '''echo "HOSTNAME:$(hostname)"
echo "OS:$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo "UPTIME:$(uptime -p)"
echo "UPTIME_SEC:$(awk '{print int($1)}' /proc/uptime)"
echo "LOAD:$(awk '{print $1", "$2", "$3}' /proc/loadavg)"
echo "MEM_USED:$(free -m | awk '/Mem/{print $3}')"
echo "MEM_TOTAL:$(free -m | awk '/Mem/{print $2}')"
echo "DISK_USED:$(df -h / | awk 'NR==2{print $3}')"
echo "DISK_TOTAL:$(df -h / | awk 'NR==2{print $2}')"
echo "DISK_PCT:$(df / | awk 'NR==2{print $5}' | tr -d '%')"
echo "===TMUX==="
if command -v tmux > /dev/null; then
    found=0
    for sock in /tmp/tmux-*/default; do
        [ -S "$sock" ] || continue
        user_dir=$(basename $(dirname "$sock"))
        uid=${user_dir#tmux-}
        if [ "$uid" = "0" ]; then
            user="root"
        else
            user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            [ -z "$user" ] && user="uid=$uid"
        fi
        sessions=$(tmux -S "$sock" ls 2>/dev/null)
        if [ -n "$sessions" ]; then
            echo "USER:$user"
            echo "$sessions"
            found=1
        fi
    done
    [ "$found" = "0" ] && echo "No active TMUX sessions."
else
    echo "TMUX is not installed."
fi
echo "===SERVICES==="
systemctl list-units --type=service --all --no-pager --no-legend | awk -F' ' '{d="";for(i=5;i<=NF;i++)d=d (i>5?" ":"")$i;print $1"|"$3"|"$4"|"d}'
'''

NAME_RE = re.compile(r'^[a-zA-Z0-9._\-@]+$')


# ---------- token & port persistence ----------

def load_token():
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    except Exception:
        return ''


def save_token(token):
    os.makedirs(INSTALL_DIR, exist_ok=True)
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    os.chmod(TOKEN_FILE, 0o600)


def load_port():
    try:
        with open(PORT_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return None


def save_port(port):
    os.makedirs(INSTALL_DIR, exist_ok=True)
    with open(PORT_FILE, 'w') as f:
        f.write(str(port))


def find_port(start=8765, end=8780):
    """Find first available port in the range."""
    for p in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', p))
            s.close()
            return p
        except OSError:
            continue
    return None


def open_firewall(port):
    """Open firewall port if ufw is active."""
    try:
        r = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
        if 'Status: active' in r.stdout:
            subprocess.run(['ufw', 'allow', f'{port}/tcp'], capture_output=True, timeout=5)
    except Exception:
        pass


def check_token():
    token = load_token()
    if not token:
        return False
    authz = request.headers.get('Authorization', '')
    if not authz.startswith('Bearer '):
        return False
    return authz[7:] == token


# ---------- auth + rate limit ----------

@app.before_request
def auth():
    if not rate_ok(request.remote_addr or 'unknown'):
        return jsonify({"error": "rate limited"}), 429

    # /health is always public (status only — no sensitive data)
    if request.path == '/health':
        return None

    # /register: public ONLY if no token set yet. After that, requires existing token.
    if request.path == '/register':
        if load_token() and not check_token():
            return jsonify({"error": "already configured — use /update-token"}), 401
        return None

    # Everything else requires token
    if not check_token():
        return jsonify({"error": "unauthorized"}), 401
    return None


# ---------- endpoints ----------

@app.route('/health')
def health():
    """Public health check. Returns port, token status, and uptime (fast file read)."""
    try:
        with open('/proc/uptime') as f:
            uptime = int(float(f.read().split()[0]))
    except Exception:
        uptime = 0
    return jsonify({"ok": True, "configured": bool(load_token()), "port": load_port(), "uptime": uptime})


@app.route('/register', methods=['POST'])
def register():
    """Manager sends a token to configure this agent. Public (no auth yet)."""
    d = request.get_json() or {}
    if 'token' not in d or not d['token']:
        return jsonify({"error": "no token provided"}), 400
    save_token(d['token'])
    return jsonify({"ok": True, "port": load_port(), "message": "Token saved. Agent is now protected."})


@app.route('/update-token', methods=['POST'])
def update_token():
    """Rotate token. Requires current token for auth (checked by @before_request)."""
    d = request.get_json() or {}
    if 'new_token' not in d or not d['new_token']:
        return jsonify({"error": "no new_token provided"}), 400
    old = load_token()
    save_token(d['new_token'])
    return jsonify({"ok": True, "old_token_prefix": old[:8] + "...", "message": "Token rotated."})


@app.route('/info')
def info():
    try:
        r = subprocess.run(['bash', '-c', INFO_CMD], capture_output=True, text=True, timeout=20)
        return jsonify({"output": r.stdout, "rc": r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "", "rc": 1, "error": "timeout"}), 504


@app.route('/tmux')
def tmux():
    """List TMUX sessions across all users (agent runs as root, so it can read every user's socket)."""
    try:
        cmd = '''found=0
for sock in /tmp/tmux-*/default; do
    [ -S "$sock" ] || continue
    user_dir=$(basename $(dirname "$sock"))
    uid=${user_dir#tmux-}
    if [ "$uid" = "0" ]; then
        user="root"
    else
        user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
        [ -z "$user" ] && user="uid=$uid"
    fi
    sessions=$(tmux -S "$sock" ls 2>/dev/null)
    if [ -n "$sessions" ]; then
        echo "USER:$user"
        echo "$sessions"
        echo ""
        found=1
    fi
done
[ "$found" = "0" ] && echo "No active TMUX sessions."'''
        r = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True, timeout=10)
        out = r.stdout.strip()
        if not out:
            check = subprocess.run(['bash', '-c', 'command -v tmux'], capture_output=True, text=True)
            if not check.stdout.strip():
                return jsonify({"output": "TMUX is not installed on this server."})
            return jsonify({"output": "No active TMUX sessions."})
        return jsonify({"output": out})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "", "error": "timeout"}), 504


@app.route('/service/<name>/<action>', methods=['POST'])
def service_control(name, action):
    if action not in ('start', 'stop', 'restart', 'status'):
        return jsonify({"error": "invalid action"}), 400
    if not NAME_RE.match(name):
        return jsonify({"error": "invalid service name"}), 400
    try:
        r = subprocess.run(['systemctl', action, name], capture_output=True, text=True, timeout=30)
        return jsonify({"ok": r.returncode == 0, "output": r.stdout + r.stderr, "rc": r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "output": "", "error": "timeout"}), 504


@app.route('/logs/<service>')
def logs(service):
    if not NAME_RE.match(service):
        return jsonify({"error": "invalid service name"}), 400
    try:
        n = max(1, min(int(request.args.get('lines', '100')), 1000))
    except ValueError:
        n = 100
    try:
        r = subprocess.run(['journalctl', '-u', service, '-n', str(n), '--no-pager'],
                           capture_output=True, text=True, timeout=15)
        return jsonify({"logs": r.stdout, "rc": r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"logs": "", "error": "timeout"}), 504


@app.route('/restart', methods=['POST'])
def restart():
    try:
        subprocess.Popen(['bash', '-c', 'sleep 3 && systemctl reboot'])
        return jsonify({"ok": True, "message": "Rebooting in 3 seconds..."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == '__main__':
    port = load_port()
    if port is None:
        port = find_port()
        if port is None:
            print("ERROR: No available port in range 8765-8780")
            raise SystemExit(1)
        save_port(port)
        print(f"Auto-selected port: {port}")

    open_firewall(port)

    token = load_token()
    if not token:
        print(f"VPS Agent starting on port {port} — waiting for manager to register a token")
    else:
        print(f"VPS Agent starting on port {port} — token configured")

    app.run(host='0.0.0.0', port=port, debug=False)
