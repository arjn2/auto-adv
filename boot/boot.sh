#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Setting up Linux Developer Mode with Service Modifications..."

# Backup original GRUB configuration
echo "Backing up GRUB configuration..."
cp /etc/default/grub /etc/default/grub.backup

# Modify GRUB configuration
echo "Modifying GRUB configuration..."
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="debug systemd.log_level=debug systemd.log_target=journal audit=1 developer_mode=1"/' /etc/default/grub

# Update GRUB
echo "Updating GRUB..."
update-grub

# Create directory for service overrides
mkdir -p /etc/systemd/system.conf.d/

# Configure system.conf override for service limits
echo "Configuring service limits..."
cat > /etc/systemd/system.conf.d/50-developer-mode.conf << EOF
[Manager]
DefaultLimitNOFILE=524288
DefaultLimitNPROC=32768
DefaultTasksMax=32768
LogLevel=debug
EOF

# Create directory for custom services
mkdir -p /etc/systemd/system/

# Create process monitor service
echo "Creating process monitor service..."
cat > /etc/systemd/system/process-monitor.service << EOF
[Unit]
Description=Process Activity Monitor Service
After=network.target auditd.service
Wants=auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/process_monitor.py
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security settings
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYSLOG CAP_SYS_PTRACE
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYSLOG CAP_SYS_PTRACE
SecureBits=keep-caps
NoNewPrivileges=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=process-monitor

# Resource limits
LimitNPROC=64
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

# Modify systemd-journald service
echo "Modifying journald service..."
mkdir -p /etc/systemd/system/systemd-journald.service.d/
cat > /etc/systemd/system/systemd-journald.service.d/override.conf << EOF
[Service]
LogLevel=debug
StandardOutput=journal
StandardError=journal
SyslogIdentifier=journald-developer

# Increase resource limits
LimitNOFILE=524288
EOF

# Modify auditd service
echo "Modifying auditd service..."
mkdir -p /etc/systemd/system/auditd.service.d/
cat > /etc/systemd/system/auditd.service.d/override.conf << EOF
[Service]
LogLevel=debug
StandardOutput=journal
StandardError=journal
SyslogIdentifier=auditd-developer

# Increase resource limits
LimitNOFILE=524288
EOF

# Enable and configure systemd services
echo "Configuring systemd services..."
systemctl enable systemd-journald.service
systemctl enable auditd.service
systemctl enable process-monitor.service

# Configure kernel parameters for developer mode
echo "Configuring kernel parameters..."
cat > /etc/sysctl.d/99-developer-mode.conf << EOF
# Enable kernel debugging
kernel.sysrq = 1
kernel.printk = 7 4 1 7

# Increase logging buffer size
kernel.printk_ratelimit = 0
kernel.printk_ratelimit_burst = 10000

# Enable core dumps
kernel.core_pattern = /var/crash/core.%e.%p.%h.%t

# Increase inotify limits for file monitoring
fs.inotify.max_user_watches = 524288
fs.inotify.max_queued_events = 524288
fs.inotify.max_user_instances = 524288
EOF

# Apply sysctl changes
sysctl --system

# Configure audit rules for better logging
echo "Configuring audit rules..."
cat > /etc/audit/rules.d/developer-mode.rules << EOF
# Log all executed commands
-a exit,always -F arch=b64 -S execve -k executed_commands

# Track file changes
-w /etc -p wa -k system_files
-w /bin -p wa -k binary_files
-w /sbin -p wa -k binary_files
-w /usr/bin -p wa -k binary_files
-w /usr/sbin -p wa -k binary_files

# Track network connections
-a exit,always -F arch=b64 -S connect -F a2!=110 -k network_connection

# Track process creation and termination
-a exit,always -F arch=b64 -S fork -S clone -S vfork -k process_creation
-a exit,always -F arch=b64 -S exit -S exit_group -k process_termination

# Track file descriptors and pipes
-a exit,always -F arch=b64 -S pipe -S pipe2 -k ipc_pipe
-a exit,always -F arch=b64 -S socket -k network_socket

# Track memory operations
-a exit,always -F arch=b64 -S mmap -S mprotect -S memfd_create -k memory_operations
EOF

# Restart audit daemon
service auditd restart

# Configure journald for persistent logging
echo "Configuring journald for persistent logging..."
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal

cat > /etc/systemd/journald.conf << EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=2G
SystemMaxFileSize=256M
SystemMaxFiles=100
ForwardToSyslog=yes
MaxRetentionSec=14day
RateLimitInterval=0
RateLimitBurst=0
EOF

# Create logging directories with proper permissions
mkdir -p /var/log/process-monitor
chmod 750 /var/log/process-monitor
chown root:systemd-journal /var/log/process-monitor

# Set up crash handling
echo "Configuring crash handling..."
mkdir -p /var/crash
chmod 777 /var/crash

# Install necessary development tools
echo "Installing development tools..."
apt-get update
apt-get install -y \
    linux-tools-common \
    linux-tools-generic \
    systemtap \
    trace-cmd \
    strace \
    ltrace \
    python3-systemd \
    python3-audit \
    auditd \
    sysstat \
    iotop \
    net-tools

# Reload systemd to apply changes
systemctl daemon-reload

# Create developer mode indicator
touch /etc/developer_mode

echo "Setup complete! System will boot in developer mode after restart."
echo "Services configured:"
echo "- process-monitor.service"
echo "- systemd-journald.service (modified)"
echo "- auditd.service (modified)"
echo ""
echo "Would you like to restart now? (y/n)"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
    echo "Rebooting system..."
    reboot
else
    echo "Please reboot manually when ready."
    echo "You can check service status after reboot with:"
    echo "systemctl status process-monitor"
    echo "systemctl status systemd-journald"
    echo "systemctl status auditd"
fi
