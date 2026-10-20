#!/usr/bin/env bash
# Uninstall VPS Agent
set -e
[ "$(id -u)" -ne 0 ] && { echo "Run as root: sudo bash uninstall.sh"; exit 1; }

echo "==> Stopping and disabling service..."
systemctl stop vps-agent 2>/dev/null || true
systemctl disable vps-agent 2>/dev/null || true
rm -f /etc/systemd/system/vps-agent.service
systemctl daemon-reload

echo "==> Removing /opt/vps-agent ..."
rm -rf /opt/vps-agent

echo "==> Done. Agent removed."
