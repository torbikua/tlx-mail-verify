#!/bin/bash
# Mail Address Verifier - Start Script

set -e

APP_NAME="mail-address-verifier"
APP_DIR="/opt/mail-address-verifier"
VENV_DIR="$APP_DIR/venv"
PID_FILE="$APP_DIR/app.pid"
LOG_DIR="$APP_DIR/logs"
PORT=8080

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cd "$APP_DIR"

# Create logs directory if not exists
mkdir -p "$LOG_DIR"

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        log_warn "Application already running with PID $OLD_PID"
        log_info "Use ./stop.sh to stop it first, or ./restart.sh to restart"
        exit 1
    else
        log_warn "Stale PID file found, removing..."
        rm -f "$PID_FILE"
    fi
fi

# Check if port is in use
if lsof -ti:$PORT > /dev/null 2>&1; then
    log_warn "Port $PORT is already in use"
    EXISTING_PID=$(lsof -ti:$PORT)
    log_info "Stopping existing process (PID: $EXISTING_PID)..."
    kill -15 "$EXISTING_PID" 2>/dev/null || true
    sleep 2
    # Force kill if still running
    if lsof -ti:$PORT > /dev/null 2>&1; then
        kill -9 "$EXISTING_PID" 2>/dev/null || true
        sleep 1
    fi
fi

# Check venv exists
if [ ! -d "$VENV_DIR" ]; then
    log_error "Virtual environment not found at $VENV_DIR"
    log_info "Run ./setup.sh first to set up the environment"
    exit 1
fi

# Check .env exists
if [ ! -f "$APP_DIR/.env" ]; then
    log_error ".env file not found"
    log_info "Copy .env.example to .env and configure it"
    exit 1
fi

log_info "Starting $APP_NAME..."

# Activate venv and start
source "$VENV_DIR/bin/activate"
export PYTHONPATH="$APP_DIR"

# Start application
nohup python3 "$APP_DIR/src/main.py" >> "$LOG_DIR/app_console.log" 2>&1 &
APP_PID=$!

# Save PID
echo "$APP_PID" > "$PID_FILE"

# Wait for startup
log_info "Waiting for application to start..."
for i in {1..15}; do
    if lsof -ti:$PORT > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check if started successfully
if lsof -ti:$PORT > /dev/null 2>&1; then
    log_info "Application started successfully!"
    echo ""
    echo "  PID:  $APP_PID"
    echo "  Web:  http://localhost:$PORT"
    echo "  Logs: ./logs.sh или tail -f $LOG_DIR/app_console.log"
    echo ""
    log_info "To stop: ./stop.sh"
else
    log_error "Failed to start application"
    log_info "Check logs: tail -f $LOG_DIR/app_console.log"
    rm -f "$PID_FILE"
    exit 1
fi
