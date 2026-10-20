#!/usr/bin/env bash
#
# VPS Agent Installer
# Usage:
#   sudo bash install.sh               # local repo
#   curl -sL <URL>/install.sh | sudo bash   # one-line remote
#
# The script will:
#   1. Install Python + Flask (if missing)
#   2. Download vps_agent.py from GitHub (if not present locally)
#   3. Ask for the token (paste the token your manager gave you)
#   4. Copy agent to /opt/vps-agent/agent.py
#   5. Save token to /opt/vps-agent/token (chmod 600)
#   6. Create + enable + start the vps-agent systemd service
#   7. Print connection info (IP, port, token)
#
set -e

INSTALL_DIR="/opt/vps-agent"
SERVICE_FILE="/etc/systemd/system/vps-agent.service"
GITHUB_RAW="https://raw.githubusercontent.com/sponge212/vps-agent/main/vps_agent.py"

[ "$(id -u)" -ne 0 ] && { echo "Run as root: sudo bash install.sh"; exit 1; }

echo "================================================"
echo "  VPS Agent Installer"
echo "================================================"
echo ""

# 1) Get the token from user
# Force read from /dev/tty because stdin is the curl pipe when run as `curl | bash`.
echo "Paste the token your manager gave you, then press Enter:"
read -r USER_TOKEN </dev/tty
[ -z "$USER_TOKEN" ] && { echo "Error: token is required. Run again."; exit 1; }
echo ""

# 2) Install Python + Flask
if ! command -v python3 > /dev/null; then
    echo "==> Installing Python3 ..."
    if   command -v apt    > /dev/null; then apt update -qq && apt install -y -qq python3 python3-pip
    elif command -v dnf    > /dev/null; then dnf install -y python3 python3-pip
    elif command -v yum    > /dev/null; then yum install -y python3 python3-pip
    elif command -v pacman > /dev/null; then pacman -S --noconfirm python python-pip
    else echo "ERROR: please install python3 + pip3 manually"; exit 1; fi
fi

echo "==> Installing Flask ..."
pip3 install --quiet --break-system-packages flask 2>/dev/null \
    || pip3 install --quiet flask

# 3) Get vps_agent.py (local copy OR download from GitHub)
TMP_FILE="/tmp/vps_agent_$$.py"
if [ -f "vps_agent.py" ]; then
    cp vps_agent.py "$TMP_FILE"
    echo "==> Using local vps_agent.py"
elif [ -f "$INSTALL_DIR/agent.py" ]; then
    echo "==> Re-using existing $INSTALL_DIR/agent.py"
    # (will be overwritten below if we have a new one)
    if [ ! -s "$TMP_FILE" ]; then cp "$INSTALL_DIR/agent.py" "$TMP_FILE"; fi
else
    echo "==> Downloading vps_agent.py from GitHub ..."
    if command -v curl > /dev/null; then
        curl -sL "$GITHUB_RAW" -o "$TMP_FILE"
    elif command -v wget > /dev/null; then
        wget -qO "$TMP_FILE" "$GITHUB_RAW"
    else
        echo "ERROR: need curl or wget to download vps_agent.py"; exit 1
    fi
    if [ ! -s "$TMP_FILE" ]; then
        echo "ERROR: download failed. Please clone the repo and run 'sudo bash install.sh' from inside it."
        exit 1
    fi
fi

# 4) Install files
mkdir -p "$INSTALL_DIR"
cp "$TMP_FILE" "$INSTALL_DIR/agent.py"
chmod 644 "$INSTALL_DIR/agent.py"
rm -f "$TMP_FILE"

echo -n "$USER_TOKEN" > "$INSTALL_DIR/token"
chmod 600 "$INSTALL_DIR/token"

# 5) systemd service
cat > "$SERVICE_FILE" <<SVCEOF
[Unit]
Description=VPS Agent (HTTP management endpoint)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable vps-agent
systemctl restart vps-agent
sleep 2

# 6) Report
PORT=$(cat "$INSTALL_DIR/port" 2>/dev/null || echo "?")
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP="<your-server-ip>"

if systemctl is-active --quiet vps-agent; then
    echo ""
    echo "================================================"
    echo "  VPS Agent installed and running!"
    echo "================================================"
    echo ""
    echo "  Server IP:    $IP"
    echo "  Agent Port:   $PORT"
    echo "  Agent Token:  $USER_TOKEN"
    echo ""
    echo "  Send these 3 values to your manager."
    echo "  (Manager will add them via: Add Server -> Agent mode)"
    echo "================================================"
else
    echo ""
    echo "ERROR: agent did not start. Check logs:"
    journalctl -u vps-agent --no-pager -n 30
    exit 1
fi
