"""
create_windows_installer.py - Windows Deployment Script
=========================================================

Creates a Windows executable using PyInstaller and generates
an installer-ready package including Npcap dependency.

Usage:
    python deploy/create_windows_installer.py
"""

import os
import sys
import shutil
import subprocess
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
INSTALLER_DIR = os.path.join(DIST_DIR, "NetWatch-Windows")

APP_NAME = "NetWatch"
_version_file = os.path.join(PROJECT_ROOT, "VERSION")
try:
    with open(_version_file, encoding="utf-8") as _vf:
        APP_VERSION = _vf.read().strip()
except FileNotFoundError:
    APP_VERSION = "0.0.0"


def check_dependencies():
    """Verify build dependencies are installed."""
    print("[1/6] Checking build dependencies...")

    try:
        import PyInstaller
        print(f"  PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("  PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # Check Npcap installer
    npcap_path = os.path.join(PROJECT_ROOT, "deploy", "npcap-installer.exe")
    if os.path.exists(npcap_path):
        print(f"  Npcap installer found: {npcap_path}")
    else:
        print("  WARNING: Npcap installer not found at deploy/npcap-installer.exe")
        print("  Download from https://npcap.com/#download and place in deploy/")


def clean_previous_builds():
    """Remove previous build artifacts."""
    print("[2/6] Cleaning previous builds...")
    for d in [BUILD_DIR, INSTALLER_DIR]:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"  Removed {d}")


def create_spec_file():
    """Generate PyInstaller spec file."""
    print("[3/6] Generating PyInstaller spec...")

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None
project_root = r'{PROJECT_ROOT}'

a = Analysis(
    [os.path.join(project_root, 'main.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'frontend'), 'frontend'),
        (os.path.join(project_root, 'database', 'schema.sql'), os.path.join('database')),
        (os.path.join(project_root, 'database', 'migrations'), os.path.join('database', 'migrations')),
        (os.path.join(project_root, 'config.py'), '.'),
    ],
    hiddenimports=[
        'scapy.all',
        'scapy.layers.inet',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'sklearn.ensemble',
        'sklearn.preprocessing',
        'pandas',
        'numpy',
        'flask',
        'flask_cors',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='{APP_NAME}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='{APP_NAME}',
)
"""

    spec_path = os.path.join(PROJECT_ROOT, "netwatch.spec")
    with open(spec_path, 'w') as f:
        f.write(spec_content)
    print(f"  Spec file: {spec_path}")
    return spec_path


def run_pyinstaller(spec_path):
    """Run PyInstaller to create the executable."""
    print("[4/6] Building executable with PyInstaller...")
    print("  This may take several minutes...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        spec_path,
    ]

    result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERROR: PyInstaller failed:\n{result.stderr}")
        sys.exit(1)

    print("  Build completed successfully")


def create_installer_package():
    """Assemble the installer package."""
    print("[5/6] Creating installer package...")

    os.makedirs(INSTALLER_DIR, exist_ok=True)

    # Copy built files
    built = os.path.join(DIST_DIR, APP_NAME)
    if os.path.exists(built):
        shutil.copytree(built, os.path.join(INSTALLER_DIR, APP_NAME), dirs_exist_ok=True)

    # Create install script
    install_bat = os.path.join(INSTALLER_DIR, "install.bat")
    with open(install_bat, 'w') as f:
        f.write(f"""@echo off
echo ============================================
echo   {APP_NAME} v{APP_VERSION} Installer
echo ============================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This installer requires Administrator privileges.
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

:: Install Npcap if not present
echo [1/3] Checking Npcap dependency...
where npcap >nul 2>&1
if %errorlevel% neq 0 (
    if exist "npcap-installer.exe" (
        echo Installing Npcap...
        npcap-installer.exe /S
    ) else (
        echo WARNING: Npcap not found. Please install from https://npcap.com
    )
) else (
    echo Npcap already installed.
)

:: Create program directory
echo [2/3] Installing {APP_NAME}...
set INSTALL_DIR=%PROGRAMFILES%\\{APP_NAME}
mkdir "%INSTALL_DIR%" 2>nul
xcopy /E /Y /Q "{APP_NAME}\\*" "%INSTALL_DIR%\\"

:: Create desktop shortcut
echo [3/3] Creating shortcuts...
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%USERPROFILE%\\Desktop\\{APP_NAME}.lnk'); $sc.TargetPath = '%INSTALL_DIR%\\{APP_NAME}.exe'; $sc.WorkingDirectory = '%INSTALL_DIR%'; $sc.Description = '{APP_NAME} Network Monitor'; $sc.Save()"

echo.
echo ============================================
echo   Installation complete!
echo   Run {APP_NAME} from your Desktop shortcut.
echo   (Run as Administrator for packet capture)
echo ============================================
pause
""")

    # Create uninstall script
    uninstall_bat = os.path.join(INSTALLER_DIR, "uninstall.bat")
    with open(uninstall_bat, 'w') as f:
        f.write(f"""@echo off
echo Uninstalling {APP_NAME}...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Requires Administrator privileges.
    pause
    exit /b 1
)

set INSTALL_DIR=%PROGRAMFILES%\\{APP_NAME}
rmdir /S /Q "%INSTALL_DIR%" 2>nul
del "%USERPROFILE%\\Desktop\\{APP_NAME}.lnk" 2>nul

echo {APP_NAME} has been uninstalled.
pause
""")

    # Create run script
    run_bat = os.path.join(INSTALLER_DIR, "run_netwatch.bat")
    with open(run_bat, 'w') as f:
        f.write(f"""@echo off
:: Run {APP_NAME} with administrator privileges
echo Starting {APP_NAME}...
cd /d "%~dp0{APP_NAME}"
{APP_NAME}.exe
pause
""")

    print(f"  Package created at: {INSTALLER_DIR}")


def create_readme():
    """Create README for the installer package."""
    print("[6/6] Creating README...")

    readme = os.path.join(INSTALLER_DIR, "README.txt")
    with open(readme, 'w') as f:
        f.write(f"""{APP_NAME} v{APP_VERSION} - Windows Installation
====================================================

SYSTEM REQUIREMENTS:
  - Windows 10 or Windows 11
  - Administrator privileges (for packet capture)
  - Npcap (included in installer)

INSTALLATION:
  1. Right-click install.bat → "Run as administrator"
  2. Follow the prompts
  3. Use the Desktop shortcut to launch

RUNNING:
  - Right-click the Desktop shortcut → "Run as administrator"
  - Open browser: http://localhost:5000

UNINSTALLING:
  - Right-click uninstall.bat → "Run as administrator"

TROUBLESHOOTING:
  - If no packets captured: Ensure Npcap is installed and run as Admin
  - If port 5000 in use: Run with --port 8080
  - Logs: Check the console output for errors

For full documentation, visit the project repository.
""")


def main():
    """Orchestrate the Windows build process."""
    print(f"Building {APP_NAME} v{APP_VERSION} for Windows")
    print("=" * 50)

    check_dependencies()
    clean_previous_builds()
    spec_path = create_spec_file()
    run_pyinstaller(spec_path)
    create_installer_package()
    create_readme()

    print()
    print("=" * 50)
    print(f"Windows installer package ready: {INSTALLER_DIR}")
    print("Distribute the NetWatch-Windows folder to users.")
    print("=" * 50)


if __name__ == "__main__":
    main()
