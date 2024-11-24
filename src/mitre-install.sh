#!/bin/bash
# mitre-install.sh
INSTALL_DIR="$(pwd)"

# Create caldera directory
mkdir -p "$INSTALL_DIR/caldera"
cd "$INSTALL_DIR/caldera"

# Install system dependencies
print_status "Installing system dependencies..."
apt update
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    golang \
    nodejs \
    npm \
    curl \
    wget \
    build-essential

# Clone Caldera repository
print_status "Cloning Caldera repository..."
git clone https://github.com/mitre/caldera.git
cd caldera

# Create and activate virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
print_status "Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# Configure Caldera
print_status "Configuring Caldera..."
cat > conf/default.yml << EOL
api_key: ADMIN123
crypto_type: clear
debug: False
api_key_blue: ADMIN123
api_key_red: ADMIN123
users:
  red:
    admin: admin
  blue:
    admin: admin
exfil_dir: /tmp/caldera
reports_dir: /tmp/caldera/reports
crypt_salt: REPLACE_WITH_RANDOM_VALUE
app.contact.http: http://0.0.0.0:8888
app.contact.tcp: 0.0.0.0:7010
app.contact.udp: 0.0.0.0:7011
plugins:
  - stockpile
  - sandcat
  - gui
  - atomic
  - response
  - compass
  - training
  - access
  - manx
  - ssl
EOL

# Create startup script
print_status "Creating startup script..."
cat > "$INSTALL_DIR/start_caldera.sh" << 'EOL'
#!/bin/bash
cd "$HOME/Desktop/mitre/caldera"
source venv/bin/activate
python3 server.py --insecure
EOL

chmod +x "$INSTALL_DIR/start_caldera.sh"

# Create shutdown script
print_status "Creating shutdown script..."
cat > "$INSTALL_DIR/stop_caldera.sh" << 'EOL'
#!/bin/bash
pkill -f "python3 server.py"
EOL

chmod +x "$INSTALL_DIR/stop_caldera.sh"

# Create service file
print_status "Creating systemd service..."
cat > /etc/systemd/system/caldera.service << EOL
[Unit]
Description=MITRE Caldera
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR/caldera
Environment=PATH=$INSTALL_DIR/caldera/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$INSTALL_DIR/caldera/venv/bin/python3 server.py --insecure
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd
systemctl daemon-reload

# Set permissions
print_status "Setting permissions..."
chown -R $SUDO_USER:$SUDO_USER "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

print_status "Installation complete!"
echo "To start Caldera, use one of these methods:"
echo "1. Run: $INSTALL_DIR/start_caldera.sh"
echo "2. Run: systemctl start caldera"
echo "3. Navigate to $INSTALL_DIR/caldera and run: python3 server.py --insecure"
echo ""
echo "Access the web interface at: http://localhost:8888"
echo "Default credentials: red/admin:admin"
echo ""
echo "To stop Caldera:"
echo "1. Run: $INSTALL_DIR/stop_caldera.sh"
echo "2. Run: systemctl stop caldera"

# Create requirements check script
cat > "$INSTALL_DIR/check_requirements.sh" << 'EOL'
#!/bin/bash

echo "Checking Caldera Requirements..."
echo "-------------------------------"

# Check Python version
python3 --version
echo "Python3: OK"

# Check pip
pip3 --version
echo "Pip3: OK"

# Check Go
go version
echo "Go: OK"

# Check Node.js
node --version
echo "Node.js: OK"

# Check npm
npm --version
echo "npm: OK"

# Check virtual environment
if [ -d "caldera/venv" ]; then
    echo "Virtual Environment: OK"
else
    echo "Virtual Environment: NOT FOUND"
fi

# Check Caldera configuration
if [ -f "caldera/conf/default.yml" ]; then
    echo "Caldera Config: OK"
else
    echo "Caldera Config: NOT FOUND"
fi

# Check service status
systemctl status caldera.service
EOL

chmod +x "$INSTALL_DIR/check_requirements.sh"

print_status "Setup complete! Check installation with: $INSTALL_DIR/check_requirements.sh"


