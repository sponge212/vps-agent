#!/usr/bin/env python3
"""
VPS Agent — lightweight HTTP agent for remote server management.

Runs as a systemd service. Listens on an auto-selected port (8765-8780).
Authenticates every request with a Bearer token stored in /opt/vps-agent/token.

Endpoints (all require token except /health and /register-if-not-configured):
    GET  /health                       -> status, uptime, port
    POST /register      {token}        -> set initial token
    POST /update-token  {new_token}    -> rotate token
    GET  /info                         -> hostname, OS, uptime, mem, disk, services
    GET  /tmux                         -> all tmux sessions across users (rich JSON)
    POST /tmux/kill      {user,session} -> kill-session
    GET  /tmux/logs?user=X&session=Y&lines=N -> capture-pane output
    POST /service/<name>/<action>      -> systemctl start/stop/restart/status
    GET  /logs/<service>?lines=N      -> journalctl tail
    POST /restart                      -> reboot server (3s delay)
    POST /update-code    {code}        -> replace agent.py and restart (auto-rollback on syntax error)
    POST /restore-code                 -> restore agent.py from .bak backup
"""
import os
import re
import json
import glob
import pwd
import shutil
import socket
import subprocess
from collections import defaultdict
from datetime import datetime
from time import time

from flask import Flask, request, jsonify

app = Flask(__name__)

INSTALL_DIR = '/opt/vps-agent'
TOKEN_FILE = os.path.join(INSTALL_DIR, 'token')
PORT_FILE = os.path.join(INSTALL_DIR, 'port')
AGENT_FILE = os.path.join(INSTALL_DIR, 'agent.py')
BACKUP_FILE = os.path.join(INSTALL_DIR, 'agent.py.bak')

# Rate limiting: 10 requests / 60s per IP (slows down brute-force scanners)
_rate = defaultdict(list)


def rate_ok(ip, max_req=10, window=60):
    now = time()
    _rate[ip] = [t for t in _rate[ip] if now - t < window]
    if len(_rate[ip]) >= max_req:
        return False
    _rate[ip].append(now)
    return True


# INFO_CMD no longer contains TMUX (we have a dedicated /tmux endpoint now)
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


# ---------- tmux helpers ----------

def _uid_to_user(uid):
    """Convert UID to username. Returns 'root' for 0, 'uid=N' if unknown."""
    if uid == 0:
        return 'root'
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f'uid={uid}'


def _user_to_uid(user):
    """Convert username to UID. Returns None on failure."""
    if user == 'root':
        return 0
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


def _find_tmux_socket(user):
    """Return the tmux socket path for the given user, or None if no socket exists."""
    uid = _user_to_uid(user)
    if uid is None:
        return None
    sock = f'/tmp/tmux-{uid}/default'
    return sock if (os.path.exists(sock) and os.path.isdir(os.path.dirname(sock))) else None


def _list_tmux_sessions_for_socket(sock, user):
    """List all tmux sessions on a single socket with full details."""
    sessions = []
    try:
        r = subprocess.run(
            ['tmux', '-S', sock, 'ls', '-F',
             '#{session_name}|#{session_windows}|#{session_created}|#{session_attached}|#{session_path}'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0 or not r.stdout.strip():
            return sessions
        for line in r.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('|')
            if len(parts) < 5:
                continue
            name, windows_str, created_str, attached_str, sess_path = parts[:5]
            try:
                created_iso = datetime.fromtimestamp(int(created_str)).isoformat()
            except Exception:
                created_iso = created_str
            panes = []
            try:
                pr = subprocess.run(
                    ['tmux', '-S', sock, 'list-panes', '-a', '-t', name, '-F',
                     '#{pane_id}|#{pane_current_command}|#{pane_pid}|#{pane_current_path}|#{window_index}'],
                    capture_output=True, text=True, timeout=5
                )
                for pline in pr.stdout.strip().split('\n'):
                    if not pline:
                        continue
                    pparts = pline.split('|')
                    if len(pparts) >= 5:
                        panes.append({
                            'id': pparts[0],
                            'command': pparts[1],
                            'pid': pparts[2],
                            'path': pparts[3],
                            'window': pparts[4]
                        })
            except Exception:
                pass
            sessions.append({
                'user': user,
                'name': name,
                'windows': int(windows_str) if windows_str.isdigit() else 0,
                'created': created_iso,
                'attached': attached_str == '1',
                'path': sess_path,
                'panes': panes
            })
    except Exception:
        pass
    return sessions


def _list_all_tmux_sessions():
    """Iterate through all /tmp/tmux-*/default sockets and collect sessions from each."""
    sessions = []
    for sock in glob.glob('/tmp/tmux-*/default'):
        # Skip if path doesn't exist (stale glob match)
        if not os.path.exists(sock):
            continue
        user_dir = os.path.basename(os.path.dirname(sock))
        uid_str = user_dir.replace('tmux-', '', 1)
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        user = _uid_to_user(uid)
        sessions.extend(_list_tmux_sessions_for_socket(sock, user))
    return sessions


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
def tmux_list():
    """List all TMUX sessions across all users with rich details (panes, attached, etc.)."""
    try:
        sessions = _list_all_tmux_sessions()
        if not sessions:
            check = subprocess.run(['bash', '-c', 'command -v tmux'], capture_output=True, text=True)
            if not check.stdout.strip():
                return jsonify({"output": "TMUX is not installed on this server.", "sessions": []})
            return jsonify({"output": "No active TMUX sessions.", "sessions": []})
        # Backward-compat text format
        text_lines = []
        for s in sessions:
            text_lines.append(f"USER:{s['user']}")
            text_lines.append(f"{s['name']}: {s['windows']} windows (created {s['created']}){' (attached)' if s['attached'] else ''}")
        return jsonify({"output": '\n'.join(text_lines), "sessions": sessions})
    except Exception as e:
        return jsonify({"output": "", "error": str(e), "sessions": []}), 500


@app.route('/tmux/kill', methods=['POST'])
def tmux_kill():
    """Kill a tmux session. Body: {"user": "bob", "session": "dev"}."""
    d = request.get_json() or {}
    user = d.get('user', '')
    session = d.get('session', '')
    if not user or not session:
        return jsonify({"error": "user and session required"}), 400
    if not NAME_RE.match(session):
        return jsonify({"error": "invalid session name"}), 400
    sock = _find_tmux_socket(user)
    if not sock:
        return jsonify({"error": f"no tmux socket for user '{user}'"}), 404
    try:
        r = subprocess.run(['tmux', '-S', sock, 'kill-session', '-t', session],
                          capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return jsonify({"ok": False, "error": r.stderr.strip() or 'kill-session failed'}), 400
        return jsonify({"ok": True, "message": f"Session '{session}' (user: {user}) killed"})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504


@app.route('/tmux/logs')
def tmux_logs():
    """Capture last N lines of a tmux pane's output.
    Query: ?user=bob&session=dev&lines=100
    """
    user = request.args.get('user', '')
    session = request.args.get('session', '')
    try:
        n = max(1, min(int(request.args.get('lines', '100')), 1000))
    except ValueError:
        n = 100
    if not user or not session:
        return jsonify({"error": "user and session required"}), 400
    if not NAME_RE.match(session):
        return jsonify({"error": "invalid session name"}), 400
    sock = _find_tmux_socket(user)
    if not sock:
        return jsonify({"error": f"no tmux socket for user '{user}'"}), 404
    try:
        r = subprocess.run(
            ['tmux', '-S', sock, 'capture-pane', '-p', '-t', session, '-S', f'-{n}'],
            capture_output=True, text=True, timeout=10
        )
        return jsonify({"logs": r.stdout, "rc": r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504


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


@app.route('/update-code', methods=['POST'])
def update_code():
    """Replace agent.py with new code from manager.
    Body: {"code": "..."} - replaces /opt/vps-agent/agent.py and restarts service.
    Auto-rolls back to backup if syntax check fails.
    """
    d = request.get_json() or {}
    code = d.get('code', '')
    if not code or len(code) < 200:
        return jsonify({"error": "no code provided or code too short"}), 400
    # Sanity check: must look like the agent
    if 'from flask import' not in code or 'INSTALL_DIR' not in code:
        return jsonify({"error": "code doesn't look like the vps-agent"}), 400
    # Backup current
    try:
        shutil.copy2(AGENT_FILE, BACKUP_FILE)
    except Exception as e:
        return jsonify({"error": f"backup failed: {e}"}), 500
    # Write to a temp file first, validate syntax, then move
    tmp_path = AGENT_FILE + '.new'
    try:
        with open(tmp_path, 'w') as f:
            f.write(code)
        # Syntax check
        r = subprocess.run(
            ['python3', '-c', f'import ast; ast.parse(open("{tmp_path}").read())'],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode != 0:
            os.unlink(tmp_path)
            return jsonify({"error": f"syntax error in new code: {r.stderr.strip()}"}), 400
        # Move into place
        os.replace(tmp_path, AGENT_FILE)
    except Exception as e:
        # Try to restore backup
        try: shutil.copy2(BACKUP_FILE, AGENT_FILE)
        except: pass
        return jsonify({"error": f"write failed: {e}"}), 500
    # Schedule restart in background (so the response can be sent first)
    subprocess.Popen(['bash', '-c', 'sleep 2 && systemctl restart vps-agent'])
    return jsonify({"ok": True, "message": "Code updated. Restarting agent in 2s..."})


@app.route('/restore-code', methods=['POST'])
def restore_code():
    """Restore agent.py from .bak backup. Useful if a bad update broke something."""
    if not os.path.exists(BACKUP_FILE):
        return jsonify({"error": "no backup exists"}), 404
    try:
        shutil.copy2(BACKUP_FILE, AGENT_FILE)
        subprocess.Popen(['bash', '-c', 'sleep 2 && systemctl restart vps-agent'])
        return jsonify({"ok": True, "message": "Restored from backup. Restarting..."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
