#!/bin/bash
# Mail Address Verifier - Restart Script

APP_DIR="/opt/mail-address-verifier"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[INFO]${NC} Restarting Mail Address Verifier..."

# Stop
"$APP_DIR/stop.sh"

# Wait a bit
sleep 2

# Start
"$APP_DIR/start.sh"
