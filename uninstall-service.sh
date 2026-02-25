#!/bin/bash
# Mail Address Verifier - Uninstall Systemd Service

SERVICE_NAME="mail-address-verifier"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Please run as root (sudo ./uninstall-service.sh)"
    exit 1
fi

echo ""
log_info "Uninstalling $SERVICE_NAME systemd service..."

# Stop service
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    log_info "Stopping service..."
    systemctl stop "$SERVICE_NAME"
fi

# Disable service
if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    log_info "Disabling service..."
    systemctl disable "$SERVICE_NAME"
fi

# Remove service file
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    log_info "Removing service file..."
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
fi

# Reload systemd
log_info "Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

log_info "Service uninstalled successfully"
echo ""
log_info "You can still run the application manually with ./start.sh"
