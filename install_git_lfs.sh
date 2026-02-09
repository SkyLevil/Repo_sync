#!/bin/bash
# Git LFS Auto-Installer for Linux and macOS
# This script automatically installs Git LFS

set -e

echo "========================================"
echo "Git LFS Auto-Installer"
echo "========================================"
echo

# Check if Git LFS is already installed
if command -v git-lfs &> /dev/null || git lfs version &> /dev/null 2>&1; then
    echo "[INFO] Git LFS is already installed!"
    git lfs version
    echo
    echo "[INFO] Running git lfs install to ensure it's configured..."
    git lfs install
    echo
    echo "[SUCCESS] Git LFS is ready to use!"
    exit 0
fi

echo "[INFO] Git LFS not found. Installing..."
echo

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux*)
        echo "[INFO] Detected Linux"

        # Detect distribution
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
        else
            DISTRO="unknown"
        fi

        echo "[INFO] Distribution: $DISTRO"

        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                echo "[INFO] Installing via apt-get..."
                sudo apt-get update
                sudo apt-get install -y git-lfs
                ;;
            fedora|rhel|centos|rocky|almalinux)
                echo "[INFO] Installing via dnf..."
                sudo dnf install -y git-lfs
                ;;
            arch|manjaro)
                echo "[INFO] Installing via pacman..."
                sudo pacman -S --noconfirm git-lfs
                ;;
            opensuse|suse)
                echo "[INFO] Installing via zypper..."
                sudo zypper install -y git-lfs
                ;;
            *)
                echo "[WARN] Unknown distribution: $DISTRO"
                echo "[INFO] Trying apt-get..."
                sudo apt-get update && sudo apt-get install -y git-lfs
                ;;
        esac
        ;;

    Darwin*)
        echo "[INFO] Detected macOS"
        if command -v brew &> /dev/null; then
            echo "[INFO] Installing via Homebrew..."
            brew install git-lfs
        else
            echo "[ERROR] Homebrew not found!"
            echo "[INFO] Please install Homebrew first: https://brew.sh/"
            echo "       Then run: brew install git-lfs"
            exit 1
        fi
        ;;

    *)
        echo "[ERROR] Unsupported operating system: $OS"
        echo "[INFO] Please install Git LFS manually: https://git-lfs.github.com/"
        exit 1
        ;;
esac

# Initialize Git LFS
echo
echo "[INFO] Initializing Git LFS..."
git lfs install

# Verify installation
echo
echo "[INFO] Verifying installation..."
if git lfs version &> /dev/null; then
    echo
    echo "========================================"
    echo "[SUCCESS] Git LFS installed!"
    echo "========================================"
    echo
    git lfs version
    echo
    echo "Next steps:"
    echo "  1. Run: python setup_git_lfs.py"
    echo "  2. Run your sync tool again"
    echo "  3. Large files will be uploaded to Git LFS"
    echo
else
    echo "[ERROR] Installation verification failed"
    exit 1
fi
