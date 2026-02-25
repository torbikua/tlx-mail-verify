#!/bin/bash
# Mail Address Verifier - Install Systemd Service

set -e

APP_DIR="/opt/mail-address-verifier"
SERVICE_NAME="mail-address-verifier"
SERVICE_FILE="$APP_DIR/$SERVICE_NAME.service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo ./install-service.sh)"
    exit 1
fi

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Installing Mail Address Verifier${NC}"
echo -e "${CYAN}  as Systemd Service${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check prerequisites
log_info "Checking prerequisites..."

if [ ! -d "$APP_DIR/venv" ]; then
    log_error "Virtual environment not found. Run ./setup.sh first"
    exit 1
fi

if [ ! -f "$APP_DIR/.env" ]; then
    log_error ".env file not found. Copy .env.example to .env and configure it"
    exit 1
fi

if [ ! -f "$SERVICE_FILE" ]; then
    log_error "Service file not found: $SERVICE_FILE"
    exit 1
fi

# Stop any running instances
log_info "Stopping any running instances..."
"$APP_DIR/stop.sh" 2>/dev/null || true
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

# Create logs directory
mkdir -p "$APP_DIR/logs"

# Copy service file
log_info "Installing systemd service..."
cp "$SERVICE_FILE" /etc/systemd/system/
chmod 644 /etc/systemd/system/$SERVICE_NAME.service

# Reload systemd
log_info "Reloading systemd daemon..."
systemctl daemon-reload

# Enable service (autostart)
log_info "Enabling service for autostart..."
systemctl enable "$SERVICE_NAME"

# Start service
log_info "Starting service..."
systemctl start "$SERVICE_NAME"

# Wait and check status
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_info "Service installed and started successfully!"
    echo ""
    systemctl status "$SERVICE_NAME" --no-pager -l | head -15
    echo ""
    echo -e "${CYAN}Service Commands:${NC}"
    echo "  systemctl status $SERVICE_NAME   - Check status"
    echo "  systemctl start $SERVICE_NAME    - Start service"
    echo "  systemctl stop $SERVICE_NAME     - Stop service"
    echo "  systemctl restart $SERVICE_NAME  - Restart service"
    echo "  systemctl disable $SERVICE_NAME  - Disable autostart"
    echo "  journalctl -u $SERVICE_NAME -f   - Follow system logs"
    echo ""
    echo -e "${GREEN}Web interface: http://localhost:8080${NC}"
else
    log_error "Service failed to start"
    echo ""
    systemctl status "$SERVICE_NAME" --no-pager -l
    echo ""
    log_info "Check logs: journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi
