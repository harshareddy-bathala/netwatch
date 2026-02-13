# NetWatch Production Deployment Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Running as a Service](#running-as-a-service)
4. [Configuration](#configuration)
5. [Log Management](#log-management)
6. [Backup & Restore](#backup--restore)
7. [Upgrades](#upgrades)
8. [Uninstallation](#uninstallation)
9. [Security Hardening](#security-hardening)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 2 cores |
| RAM | 2 GB |
| Disk | 1 GB free |
| Python | **3.11** (required — other versions not supported) |
| OS | Windows 10+, Ubuntu 22.04+, macOS 12+ |
| Network | Npcap (Windows) or libpcap (Linux/macOS) |
| Privileges | Administrator / root |

### Recommended for Production

| Component | Recommendation |
|-----------|---------------|
| CPU | 4 cores |
| RAM | 4 GB |
| Disk | 10 GB (for database and logs) |
| Network | Gigabit Ethernet |

---

## Installation

### Windows

```powershell
# 1. Install Python 3.11 from https://www.python.org/downloads/release/python-3110/
# 2. Install Npcap from https://npcap.com (select "Install in WinPcap API-compatible Mode")

# 3. Clone and setup
git clone https://github.com/your-team/netwatch.git
cd netwatch

# Create venv specifically with Python 3.11
py -3.11 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 4. Initialize database
python database/init_db.py

# 5. Run (as Administrator)
python main.py
```

**One-Click Installer:**
```powershell
# Build installer
python deploy/create_windows_installer.py

# Run installer (as Administrator)
dist\NetWatch-Windows\install.bat
```

### Linux (Ubuntu/Debian)

```bash
# 1. Install dependencies
sudo apt update
sudo apt install -y python3.11 python3.11-venv libpcap-dev

# 2. Clone and setup
git clone https://github.com/your-team/netwatch.git
cd netwatch
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Initialize database
python database/init_db.py

# 4. Run
sudo venv/bin/python main.py
```

**DEB Package:**
```bash
# Build package
chmod +x deploy/create_deb_package.sh
./deploy/create_deb_package.sh

# Install
sudo apt install ./dist/netwatch_2.0.0_amd64.deb
```

### macOS

```bash
# 1. Install Python 3.11 (via Homebrew)
brew install python@3.11

# 2. Clone and setup
git clone https://github.com/your-team/netwatch.git
cd netwatch
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run
sudo python3 main.py
```

**App Bundle:**
```bash
chmod +x deploy/create_macos_app.sh
./deploy/create_macos_app.sh
# Drag NetWatch.app to /Applications
```

---

## Running as a Service

### Linux (systemd)

The DEB package installs a systemd service automatically. Manual setup:

```bash
# Create service file
sudo cat > /usr/lib/systemd/system/netwatch.service << 'EOF'
[Unit]
Description=NetWatch Network Monitoring
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netwatch
Environment=NETWATCH_ENV=production
ExecStart=/opt/netwatch/venv/bin/python main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable netwatch
sudo systemctl start netwatch

# Check status
sudo systemctl status netwatch

# View logs
sudo journalctl -u netwatch -f
```

### Windows (as a Service)

Using NSSM (Non-Sucking Service Manager):

```powershell
# Download NSSM from https://nssm.cc
nssm install NetWatch "C:\Program Files\NetWatch\NetWatch.exe"
nssm set NetWatch AppDirectory "C:\Program Files\NetWatch"
nssm set NetWatch AppEnvironmentExtra "NETWATCH_ENV=production"
nssm start NetWatch
```

Or using Task Scheduler:
```powershell
schtasks /create /tn "NetWatch" /tr "python C:\netwatch\main.py" /sc onstart /ru SYSTEM /rl HIGHEST
```

### macOS (launchd)

```bash
sudo cat > /Library/LaunchDaemons/com.netwatch.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.netwatch</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/netwatch/venv/bin/python</string>
        <string>/opt/netwatch/main.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/opt/netwatch</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NETWATCH_ENV</key>
        <string>production</string>
    </dict>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.netwatch.plist
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWATCH_ENV` | `development` | Environment: `development`, `production`, `testing` |
| `SECRET_KEY` | `dev-secret-...` | Flask secret key (**MUST change in production**) |
| `SMTP_SERVER` | `localhost` | Email server for notifications |
| `SMTP_PORT` | `587` | SMTP port |

### Production Configuration

```bash
# Set environment
export NETWATCH_ENV=production
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Run
python main.py --port 5000
```

---

## Log Management

### Log Locations

| Platform | Path |
|----------|------|
| Linux (systemd) | `journalctl -u netwatch` |
| Linux (file) | `/var/log/netwatch/netwatch.log` |
| Windows | Console output or `logs/netwatch.log` |
| macOS | Console output or `logs/netwatch.log` |

### Log Rotation

Production mode automatically enables file-based logging with rotation:
- Max file size: 10 MB
- Keeps 10 backup files
- Total max: ~110 MB

---

## Backup & Restore

### Backup

```bash
# Stop service first
sudo systemctl stop netwatch

# Backup database
cp /var/lib/netwatch/netwatch.db /backup/netwatch_$(date +%Y%m%d).db

# Backup config
cp /opt/netwatch/config.py /backup/

# Restart
sudo systemctl start netwatch
```

### Restore

```bash
sudo systemctl stop netwatch
cp /backup/netwatch_20240101.db /var/lib/netwatch/netwatch.db
sudo systemctl start netwatch
```

---

## Upgrades

```bash
# 1. Stop the service
sudo systemctl stop netwatch

# 2. Backup
cp /var/lib/netwatch/netwatch.db /tmp/netwatch_backup.db

# 3. Update code
cd /opt/netwatch
git pull origin main

# 4. Update dependencies
venv/bin/pip install -r requirements.txt

# 5. Run database migrations
NETWATCH_ENV=production venv/bin/python -c "
from database.init_db import initialize_database
initialize_database()
"

# 6. Restart
sudo systemctl start netwatch
```

---

## Uninstallation

### Linux (DEB package)

```bash
sudo apt remove netwatch        # Keep config and data
sudo apt purge netwatch         # Remove everything
```

### Linux (manual)

```bash
sudo systemctl stop netwatch
sudo systemctl disable netwatch
sudo rm /usr/lib/systemd/system/netwatch.service
sudo systemctl daemon-reload
sudo rm -rf /opt/netwatch
sudo rm -rf /var/lib/netwatch
sudo rm -rf /var/log/netwatch
```

### Windows

```powershell
# Run uninstaller
dist\NetWatch-Windows\uninstall.bat

# Or manually
nssm remove NetWatch confirm
rmdir /S /Q "C:\Program Files\NetWatch"
```

### macOS

```bash
sudo launchctl unload /Library/LaunchDaemons/com.netwatch.plist
sudo rm /Library/LaunchDaemons/com.netwatch.plist
sudo rm -rf /Applications/NetWatch.app
rm -rf ~/.netwatch
```

---

## Security Hardening

### Production Checklist

- [ ] Set `NETWATCH_ENV=production`
- [ ] Set a strong `SECRET_KEY` environment variable
- [ ] Flask debug mode is `OFF` (automatic in production)
- [ ] Bind only to `127.0.0.1` (use reverse proxy for external access)
- [ ] Set proper file permissions (`chmod 750` on database directory)
- [ ] Configure firewall to allow only port 5000 from trusted IPs
- [ ] Use HTTPS via reverse proxy (nginx/Apache)

### Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name netwatch.example.com;

    ssl_certificate /etc/ssl/certs/netwatch.pem;
    ssl_certificate_key /etc/ssl/private/netwatch-key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
