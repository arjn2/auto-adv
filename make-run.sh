#!/bin/bash
# install_and_run.sh

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Get current directory
INSTALL_DIR="$(pwd)"

# Print status function
print_status() {
    echo -e "${GREEN}[*] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
}

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

# Create directory structure
print_status "Creating directory structure..."
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/captures"

# Install system dependencies
print_status "Installing system dependencies..."
apt update
apt install -y python3-pip python3-venv tcpdump

# Create and activate virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
print_status "Installing Python packages..."
pip install watchdog python-dotenv psutil

# Set permissions
print_status "Setting permissions..."
chmod 755 "$INSTALL_DIR"
chown -R $SUDO_USER:$SUDO_USER "$INSTALL_DIR"

# Create service file
print_status "Creating systemd service..."
cat > /etc/systemd/system/logcollector.service << EOL
[Unit]
Description=Log Collection Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/src/collectors/basic_collector.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd
systemctl daemon-reload
systemctl enable logcollector.service

print_status "Installation complete!"
print_status "Starting log collection service..."
systemctl start logcollector.service

echo "Log collection is now running as a service"
echo "To check status: systemctl status logcollector"
echo "To stop service: systemctl stop logcollector"
echo "Logs will be stored in: $INSTALL_DIR/logs"
