#!/bin/bash
# Mail Address Verifier - Status Script

APP_NAME="mail-address-verifier"
APP_DIR="/opt/mail-address-verifier"
PID_FILE="$APP_DIR/app.pid"
LOG_DIR="$APP_DIR/logs"
PORT=8080

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Mail Address Verifier - Status${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check systemd service
if systemctl is-active --quiet mail-address-verifier 2>/dev/null; then
    echo -e "${GREEN}Systemd Service:${NC} ACTIVE"
    systemctl status mail-address-verifier --no-pager -l 2>/dev/null | head -5
    echo ""
fi

# Check if running
RUNNING=0
PID=""

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        RUNNING=1
    fi
fi

# Fallback: check port
if [ $RUNNING -eq 0 ] && lsof -ti:$PORT > /dev/null 2>&1; then
    PID=$(lsof -ti:$PORT | head -1)
    RUNNING=1
fi

if [ $RUNNING -eq 1 ]; then
    echo -e "${GREEN}Status:${NC} RUNNING"
    echo -e "${GREEN}PID:${NC}    $PID"
    echo -e "${GREEN}Port:${NC}   $PORT"
    echo -e "${GREEN}Web:${NC}    http://localhost:$PORT"
    echo ""

    # Process info
    echo -e "${CYAN}Process Info:${NC}"
    ps -p "$PID" -o pid,ppid,user,%cpu,%mem,etime,command --no-headers 2>/dev/null | head -1
    echo ""

    # Memory usage
    if command -v pmap > /dev/null 2>&1; then
        MEM=$(pmap -x "$PID" 2>/dev/null | tail -1 | awk '{print $3}')
        if [ -n "$MEM" ]; then
            echo -e "${CYAN}Memory:${NC} ${MEM}KB"
        fi
    fi

    # Check web endpoint
    echo ""
    echo -e "${CYAN}Health Check:${NC}"
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT" 2>/dev/null | grep -q "200\|302"; then
        echo -e "  Web server: ${GREEN}OK${NC}"
    else
        echo -e "  Web server: ${YELLOW}Not responding${NC}"
    fi

    # Recent logs
    if [ -f "$LOG_DIR/app.log" ]; then
        echo ""
        echo -e "${CYAN}Recent Logs (last 5 lines):${NC}"
        tail -5 "$LOG_DIR/app.log" 2>/dev/null
    fi
else
    echo -e "${RED}Status:${NC} NOT RUNNING"
    echo ""
    echo "To start the application:"
    echo "  ./start.sh           - Start manually"
    echo "  systemctl start mail-address-verifier  - Start via systemd"
fi

echo ""
echo -e "${CYAN}Commands:${NC}"
echo "  ./start.sh     - Start application"
echo "  ./stop.sh      - Stop application"
echo "  ./restart.sh   - Restart application"
echo "  ./status.sh    - Show this status"
echo "  ./logs.sh      - Follow logs"
echo ""
