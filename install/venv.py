#!/bin/bash

# Create directory structure
mkdir -p ~/Desktop/logc
cd ~/Desktop/logc

# Install required system packages
sudo apt update
sudo apt install -y python3-pip python3-venv tcpdump

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install required Python packages
pip install watchdog
pip install python-dotenv
pip install psutil

# Create log directories
mkdir -p logs
mkdir -p captures

# Set permissions
sudo chmod 755 ~/Desktop/logc
sudo chown -R $USER:$USER ~/Desktop/logc

echo "Virtual environment setup complete in ~/Desktop/logc/"
echo "To activate the virtual environment, use: source ~/Desktop/logc/venv/bin/activate"
