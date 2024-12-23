#!/bin/bash

# Install required system packages
sudo apt update
sudo apt install -y python3-pip python3-venv tcpdump

cd ./
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source ./venv/bin/activate

# Install required Python packages

pip install -r requirements.txt 


# Create log directories
mkdir -p logs
mkdir -p captures

# Set permissions
sudo chmod 755 ./
sudo chown -R $USER:$USER ./

echo "Virtual environment setup complete in $PWD"
echo "To activate the virtual environment, use: source $PWD/venv/bin/activate"
