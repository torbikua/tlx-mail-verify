#!/bin/bash
# Mail Address Verifier - Logs Script

APP_DIR="/opt/mail-address-verifier"
LOG_DIR="$APP_DIR/logs"

# Colors
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    echo ""
    echo -e "${CYAN}Mail Address Verifier - Log Viewer${NC}"
    echo ""
    echo "Usage: ./logs.sh [options]"
    echo ""
    echo "Options:"
    echo "  -f, --follow     Follow log output (default)"
    echo "  -n, --lines N    Show last N lines (default: 50)"
    echo "  -c, --console    Show console log instead of app log"
    echo "  -a, --all        Show all log files"
    echo "  -h, --help       Show this help"
    echo ""
}

LOG_FILE="$LOG_DIR/app_console.log"
LINES=50
FOLLOW=1

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--follow)
            FOLLOW=1
            shift
            ;;
        -n|--lines)
            LINES="$2"
            FOLLOW=0
            shift 2
            ;;
        -c|--console)
            LOG_FILE="$LOG_DIR/app_console.log"
            shift
            ;;
        -a|--all)
            echo -e "${CYAN}Available log files:${NC}"
            ls -la "$LOG_DIR"/*.log 2>/dev/null || echo "No log files found"
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    echo "The application may not have started yet."
    exit 1
fi

if [ $FOLLOW -eq 1 ]; then
    echo -e "${CYAN}Following $LOG_FILE (Ctrl+C to stop)${NC}"
    echo ""
    tail -f "$LOG_FILE"
else
    echo -e "${CYAN}Last $LINES lines from $LOG_FILE${NC}"
    echo ""
    tail -n "$LINES" "$LOG_FILE"
fi
