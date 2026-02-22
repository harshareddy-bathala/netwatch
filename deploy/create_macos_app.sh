#!/usr/bin/env bash
#
# create_macos_app.sh - macOS Deployment Script
# =================================================
#
# Creates a macOS .app bundle for NetWatch.
#
# Usage:
#   chmod +x deploy/create_macos_app.sh
#   ./deploy/create_macos_app.sh
#

set -euo pipefail

APP_NAME="NetWatch"
APP_VERSION=$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "0.0.0")
BUNDLE_ID="com.netwatch.app"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_ROOT/dist"
APP_BUNDLE="$DIST_DIR/${APP_NAME}.app"

echo "============================================"
echo "  Building ${APP_NAME} v${APP_VERSION} for macOS"
echo "============================================"

# -----------------------------------------------
# 1. Clean
# -----------------------------------------------
echo "[1/5] Cleaning previous builds..."
rm -rf "$APP_BUNDLE"
mkdir -p "$DIST_DIR"

# -----------------------------------------------
# 2. Create .app bundle structure
# -----------------------------------------------
echo "[2/5] Creating .app bundle structure..."

mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
mkdir -p "$APP_BUNDLE/Contents/Resources/app"

# -----------------------------------------------
# 3. Create Info.plist
# -----------------------------------------------
echo "[3/5] Creating Info.plist..."

cat > "$APP_BUNDLE/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleVersion</key>
    <string>${APP_VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${APP_VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleExecutable</key>
    <string>netwatch</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2024 NetWatch Team. MIT License.</string>
</dict>
</plist>
EOF

# -----------------------------------------------
# 4. Copy application files and create launcher
# -----------------------------------------------
echo "[4/5] Copying application files..."

for item in main.py config.py requirements.txt \
            backend database alerts packet_capture frontend; do
    cp -r "$PROJECT_ROOT/$item" "$APP_BUNDLE/Contents/Resources/app/"
done

# Create launcher script
cat > "$APP_BUNDLE/Contents/MacOS/netwatch" << 'LAUNCHER'
#!/usr/bin/env bash
#
# NetWatch macOS Launcher
#
DIR="$(cd "$(dirname "$0")/../Resources/app" && pwd)"

# Check for Python 3
PYTHON=""
for candidate in python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if command -v "$candidate" > /dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    osascript -e 'display dialog "Python 3.10+ is required but not found.\nInstall from https://python.org" buttons {"OK"} default button "OK" with icon stop with title "NetWatch"'
    exit 1
fi

# Create/use virtual environment
VENV_DIR="$HOME/.netwatch/venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Setting up NetWatch environment..."
    mkdir -p "$HOME/.netwatch"
    "$PYTHON" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install -r "$DIR/requirements.txt"
fi

# Check for sudo (needed for packet capture)
if [ "$(id -u)" != "0" ]; then
    osascript -e 'display dialog "NetWatch needs administrator access for network monitoring.\nIt will ask for your password." buttons {"Cancel", "Continue"} default button "Continue" with title "NetWatch"'
    if [ $? -eq 0 ]; then
        cd "$DIR"
        osascript -e "do shell script \"cd '$DIR' && '$VENV_DIR/bin/python' main.py\" with administrator privileges"
    fi
else
    cd "$DIR"
    "$VENV_DIR/bin/python" main.py
fi

# Open browser
sleep 3
open "http://localhost:5000"
LAUNCHER
chmod +x "$APP_BUNDLE/Contents/MacOS/netwatch"

# -----------------------------------------------
# 5. Create DMG (optional - requires create-dmg)
# -----------------------------------------------
echo "[5/5] Build complete."

echo ""
echo "============================================"
echo "  App bundle: $APP_BUNDLE"
echo ""
echo "  To install:"
echo "    1. Drag ${APP_NAME}.app to /Applications"
echo "    2. Double-click to run"
echo ""
echo "  To create a DMG:"
echo "    brew install create-dmg"
echo "    create-dmg '${APP_NAME}-${APP_VERSION}.dmg' '$APP_BUNDLE'"
echo ""
echo "  To sign (optional):"
echo "    codesign --sign 'Developer ID' '$APP_BUNDLE'"
echo "============================================"
