#!/bin/bash
# Mail Address Verifier - Stop Script

APP_NAME="mail-address-verifier"
APP_DIR="/opt/mail-address-verifier"
PID_FILE="$APP_DIR/app.pid"
PORT=8080

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Stopping $APP_NAME..."

STOPPED=0

# Stop by PID file
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        log_info "Stopping process with PID $PID..."
        kill -15 "$PID" 2>/dev/null

        # Wait for graceful shutdown
        for i in {1..10}; do
            if ! ps -p "$PID" > /dev/null 2>&1; then
                break
            fi
            sleep 1
        done

        # Force kill if still running
        if ps -p "$PID" > /dev/null 2>&1; then
            log_warn "Process didn't stop gracefully, forcing..."
            kill -9 "$PID" 2>/dev/null
            sleep 1
        fi
        STOPPED=1
    fi
    rm -f "$PID_FILE"
fi

# Also check and kill any processes on port
if lsof -ti:$PORT > /dev/null 2>&1; then
    PORT_PIDS=$(lsof -ti:$PORT)
    log_info "Stopping processes on port $PORT: $PORT_PIDS"
    echo "$PORT_PIDS" | xargs kill -15 2>/dev/null || true
    sleep 2

    # Force kill remaining
    if lsof -ti:$PORT > /dev/null 2>&1; then
        lsof -ti:$PORT | xargs kill -9 2>/dev/null || true
    fi
    STOPPED=1
fi

# Kill any remaining python main.py processes
MAIN_PIDS=$(pgrep -f "python3.*src/main.py" 2>/dev/null || true)
if [ -n "$MAIN_PIDS" ]; then
    log_info "Cleaning up remaining processes: $MAIN_PIDS"
    echo "$MAIN_PIDS" | xargs kill -15 2>/dev/null || true
    sleep 1
    pgrep -f "python3.*src/main.py" | xargs kill -9 2>/dev/null || true
    STOPPED=1
fi

if [ $STOPPED -eq 1 ]; then
    log_info "Application stopped"
else
    log_warn "Application was not running"
fi
