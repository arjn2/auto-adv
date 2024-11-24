#!/bin/bash
# venv.sh
INSTALL_DIR="$(pwd)"

# Create directory structure
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/captures"

# Install required system packages
sudo apt update
sudo apt install -y python3-pip python3-venv tcpdump

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages
pip install watchdog python-dotenv psutil

# Set permissions
sudo chmod 755 "$INSTALL_DIR"
sudo chown -R $USER:$USER "$INSTALL_DIR"
