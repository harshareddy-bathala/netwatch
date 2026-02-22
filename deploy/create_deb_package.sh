#!/usr/bin/env bash
#
# create_deb_package.sh - Linux Deployment Script
# ===================================================
#
# Creates a .deb package for Debian/Ubuntu with systemd service.
#
# Usage:
#   chmod +x deploy/create_deb_package.sh
#   ./deploy/create_deb_package.sh
#

set -euo pipefail

APP_NAME="netwatch"
APP_VERSION=$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.0.0")
ARCH="amd64"
MAINTAINER="NetWatch Team <netwatch@example.com>"
DESCRIPTION="Intelligent network traffic monitoring and analysis system"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/dist/${APP_NAME}_${APP_VERSION}_${ARCH}"

echo "============================================"
echo "  Building ${APP_NAME} v${APP_VERSION} .deb"
echo "============================================"

# -----------------------------------------------
# 1. Clean previous builds
# -----------------------------------------------
echo "[1/6] Cleaning previous builds..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# -----------------------------------------------
# 2. Create directory structure
# -----------------------------------------------
echo "[2/6] Creating package structure..."

mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/opt/netwatch"
mkdir -p "$BUILD_DIR/var/lib/netwatch"
mkdir -p "$BUILD_DIR/var/log/netwatch"
mkdir -p "$BUILD_DIR/etc/netwatch"
mkdir -p "$BUILD_DIR/usr/lib/systemd/system"
mkdir -p "$BUILD_DIR/usr/local/bin"

# -----------------------------------------------
# 3. Copy application files
# -----------------------------------------------
echo "[3/6] Copying application files..."

# Copy Python source
for item in main.py config.py requirements.txt \
            backend database alerts packet_capture frontend; do
    cp -r "$PROJECT_ROOT/$item" "$BUILD_DIR/opt/netwatch/"
done

# Create launcher script
cat > "$BUILD_DIR/usr/local/bin/netwatch" << 'LAUNCHER'
#!/usr/bin/env bash
# NetWatch launcher
cd /opt/netwatch
exec python3 main.py "$@"
LAUNCHER
chmod +x "$BUILD_DIR/usr/local/bin/netwatch"

# -----------------------------------------------
# 4. Create systemd service
# -----------------------------------------------
echo "[4/6] Creating systemd service..."

cat > "$BUILD_DIR/usr/lib/systemd/system/netwatch.service" << 'SERVICE'
[Unit]
Description=NetWatch Network Monitoring System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netwatch
Environment=NETWATCH_ENV=production
ExecStart=/opt/netwatch/venv/bin/python main.py
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netwatch

# Security hardening
ProtectHome=true
NoNewPrivileges=false
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
SERVICE

# Create logrotate config
cat > "$BUILD_DIR/etc/netwatch/logrotate.conf" << 'LOGROTATE'
/var/log/netwatch/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl reload netwatch > /dev/null 2>&1 || true
    endscript
}
LOGROTATE

# -----------------------------------------------
# 5. Create Debian control files
# -----------------------------------------------
echo "[5/6] Creating DEBIAN control files..."

cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: ${APP_NAME}
Version: ${APP_VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.10), python3-pip, python3-venv, libpcap-dev
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 NetWatch provides real-time network traffic monitoring,
 device discovery, anomaly detection, and a web-based dashboard.
 Supports hotspot, WiFi client, ethernet, and port mirror modes.
Homepage: https://github.com/your-team/netwatch
EOF

# Post-install script
cat > "$BUILD_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

echo "Setting up NetWatch..."

# Create virtual environment
if [ ! -d /opt/netwatch/venv ]; then
    python3 -m venv /opt/netwatch/venv
fi

# Install dependencies
/opt/netwatch/venv/bin/pip install --upgrade pip
/opt/netwatch/venv/bin/pip install -r /opt/netwatch/requirements.txt

# Initialize database
cd /opt/netwatch
NETWATCH_ENV=production /opt/netwatch/venv/bin/python -c "
from database.init_db import initialize_database
initialize_database()
"

# Set permissions
chown -R root:root /opt/netwatch
chmod -R 755 /opt/netwatch
chmod 750 /var/lib/netwatch
chmod 750 /var/log/netwatch

# Enable and start service
systemctl daemon-reload
systemctl enable netwatch
systemctl start netwatch

echo ""
echo "============================================"
echo "  NetWatch installed successfully!"
echo "  Dashboard: http://localhost:5000"
echo ""
echo "  Manage service:"
echo "    sudo systemctl start netwatch"
echo "    sudo systemctl stop netwatch"
echo "    sudo systemctl status netwatch"
echo "    sudo journalctl -u netwatch -f"
echo "============================================"
POSTINST
chmod +x "$BUILD_DIR/DEBIAN/postinst"

# Pre-remove script
cat > "$BUILD_DIR/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
set -e
echo "Stopping NetWatch service..."
systemctl stop netwatch 2>/dev/null || true
systemctl disable netwatch 2>/dev/null || true
PRERM
chmod +x "$BUILD_DIR/DEBIAN/prerm"

# Post-remove script
cat > "$BUILD_DIR/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
set -e
if [ "$1" = "purge" ]; then
    rm -rf /opt/netwatch
    rm -rf /var/lib/netwatch
    rm -rf /var/log/netwatch
    rm -rf /etc/netwatch
fi
systemctl daemon-reload
POSTRM
chmod +x "$BUILD_DIR/DEBIAN/postrm"

# -----------------------------------------------
# 6. Build the .deb package
# -----------------------------------------------
echo "[6/6] Building .deb package..."

cd "$PROJECT_ROOT/dist"
dpkg-deb --build "${APP_NAME}_${APP_VERSION}_${ARCH}"

DEB_FILE="$PROJECT_ROOT/dist/${APP_NAME}_${APP_VERSION}_${ARCH}.deb"

echo ""
echo "============================================"
echo "  Package built: $DEB_FILE"
echo ""
echo "  Install with:"
echo "    sudo dpkg -i ${APP_NAME}_${APP_VERSION}_${ARCH}.deb"
echo ""
echo "  Or with apt (resolves deps):"
echo "    sudo apt install ./${APP_NAME}_${APP_VERSION}_${ARCH}.deb"
echo "============================================"
