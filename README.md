# VPS Agent

### Lightweight agent for remote server management.

# Install

### Run on your VPS as root:

`curl -sL https://raw.githubusercontent.com/sponge212/vps-agent/main/install.sh | sudo bash`

Paste your token when asked.

The script prints your IP, port, and token. Send them to your manager.

Uninstall

`curl -sL https://raw.githubusercontent.com/sponge212/vps-agent/main/uninstall.sh | sudo bash`

Manage

`sudo systemctl status vps-agentsudo systemctl restart vps-agentsudo journalctl -u vps-agent -f`
