#!/usr/bin/env python3
"""
Automatic Git LFS installer for Windows, Linux, and macOS.
This script detects your OS and installs Git LFS automatically.

Usage: python install_git_lfs.py
"""

import os
import platform
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


def run_command(cmd, description, check=True, shell=False):
    """Run a command and handle errors."""
    print(f"[RUN] {description}")
    print(f"      Command: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=300,
            check=check
        )

        if result.stdout.strip():
            print(f"[OUTPUT] {result.stdout.strip()}")

        if result.returncode == 0:
            print(f"[SUCCESS] {description}")
            return True
        else:
            if result.stderr.strip():
                print(f"[ERROR] {result.stderr.strip()}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed: {e}")
        if e.stderr:
            print(f"[ERROR] {e.stderr}")
        return False
    except Exception as e:
        print(f"[ERROR] {description} failed: {e}")
        return False


def check_git_lfs_installed():
    """Check if Git LFS is already installed."""
    try:
        result = subprocess.run(
            ["git", "lfs", "version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"[INFO] Git LFS is already installed: {result.stdout.strip()}")
            return True
    except Exception:
        pass
    return False


def install_windows():
    """Install Git LFS on Windows."""
    print("\n[INFO] Installing Git LFS on Windows...")

    # Try Chocolatey first
    print("[INFO] Trying Chocolatey installation...")
    if run_command(
        "choco install git-lfs -y",
        "Install Git LFS via Chocolatey",
        check=False,
        shell=True
    ):
        return True

    # Try Scoop
    print("[INFO] Trying Scoop installation...")
    if run_command(
        "scoop install git-lfs",
        "Install Git LFS via Scoop",
        check=False,
        shell=True
    ):
        return True

    # Manual download and install
    print("[INFO] Downloading Git LFS installer...")
    url = "https://github.com/git-lfs/git-lfs/releases/download/v3.4.1/git-lfs-windows-v3.4.1.exe"

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            installer_path = Path(tmpdir) / "git-lfs-installer.exe"

            print(f"[INFO] Downloading from: {url}")
            urllib.request.urlretrieve(url, installer_path)
            print(f"[INFO] Downloaded to: {installer_path}")

            # Run installer
            print("[INFO] Running installer...")
            print("[INFO] Please follow the installation wizard.")

            result = subprocess.run(
                [str(installer_path)],
                timeout=600
            )

            if result.returncode == 0:
                print("[SUCCESS] Git LFS installer completed")
                return True
            else:
                print("[ERROR] Installer failed")
                return False

    except Exception as e:
        print(f"[ERROR] Manual installation failed: {e}")
        print("\n[INFO] Please install Git LFS manually:")
        print("       1. Visit: https://git-lfs.github.com/")
        print("       2. Download and run the installer")
        print("       3. Run this script again")
        return False


def install_linux():
    """Install Git LFS on Linux."""
    print("\n[INFO] Installing Git LFS on Linux...")

    # Detect Linux distribution
    distro = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    distro = line.split("=")[1].strip().strip('"').lower()
                    break
    except Exception:
        pass

    print(f"[INFO] Detected distribution: {distro or 'unknown'}")

    # Try distribution-specific package managers
    if distro in ["ubuntu", "debian", "linuxmint", "pop"]:
        print("[INFO] Using apt-get...")
        commands = [
            ("sudo apt-get update", "Update package list"),
            ("sudo apt-get install -y git-lfs", "Install Git LFS"),
        ]
    elif distro in ["fedora", "rhel", "centos", "rocky", "almalinux"]:
        print("[INFO] Using dnf/yum...")
        commands = [
            ("sudo dnf install -y git-lfs", "Install Git LFS"),
        ]
    elif distro in ["arch", "manjaro"]:
        print("[INFO] Using pacman...")
        commands = [
            ("sudo pacman -S --noconfirm git-lfs", "Install Git LFS"),
        ]
    elif distro in ["opensuse", "suse"]:
        print("[INFO] Using zypper...")
        commands = [
            ("sudo zypper install -y git-lfs", "Install Git LFS"),
        ]
    else:
        print("[WARN] Unknown distribution, trying generic installation...")
        commands = [
            ("sudo apt-get install -y git-lfs", "Install Git LFS (apt)"),
        ]

    for cmd, desc in commands:
        if run_command(cmd, desc, check=False, shell=True):
            return True

    print("\n[ERROR] Automatic installation failed.")
    print("[INFO] Please install Git LFS manually:")
    print("       Ubuntu/Debian: sudo apt-get install git-lfs")
    print("       Fedora/RHEL:   sudo dnf install git-lfs")
    print("       Arch:          sudo pacman -S git-lfs")
    return False


def install_macos():
    """Install Git LFS on macOS."""
    print("\n[INFO] Installing Git LFS on macOS...")

    # Try Homebrew
    print("[INFO] Trying Homebrew installation...")
    if run_command(
        ["brew", "install", "git-lfs"],
        "Install Git LFS via Homebrew",
        check=False
    ):
        return True

    print("\n[ERROR] Homebrew installation failed.")
    print("[INFO] Please install Git LFS manually:")
    print("       1. Install Homebrew: https://brew.sh/")
    print("       2. Run: brew install git-lfs")
    print("       Or visit: https://git-lfs.github.com/")
    return False


def initialize_git_lfs():
    """Initialize Git LFS globally."""
    print("\n[INFO] Initializing Git LFS...")
    return run_command(
        ["git", "lfs", "install"],
        "Initialize Git LFS globally",
        check=False
    )


def main():
    """Main installation routine."""
    print("=" * 60)
    print("Git LFS Automatic Installer")
    print("=" * 60)

    # Check if already installed
    if check_git_lfs_installed():
        print("[INFO] Git LFS is already installed. Nothing to do.")
        return 0

    # Detect OS
    system = platform.system().lower()
    print(f"\n[INFO] Detected operating system: {system}")

    # Install based on OS
    success = False
    if system == "windows":
        success = install_windows()
    elif system == "linux":
        success = install_linux()
    elif system == "darwin":
        success = install_macos()
    else:
        print(f"[ERROR] Unsupported operating system: {system}")
        return 1

    if not success:
        print("\n[ERROR] Installation failed. Please install Git LFS manually.")
        print("[INFO] Visit: https://git-lfs.github.com/")
        return 1

    # Initialize Git LFS
    if not initialize_git_lfs():
        print("[WARN] Git LFS initialization failed, but installation succeeded.")
        print("[INFO] You may need to run: git lfs install")

    # Verify installation
    print("\n[INFO] Verifying installation...")
    if check_git_lfs_installed():
        print("\n" + "=" * 60)
        print("[SUCCESS] Git LFS installed successfully!")
        print("=" * 60)
        print("\n[INFO] Next steps:")
        print("  1. Run: python setup_git_lfs.py")
        print("  2. Run the sync tool again")
        print("  3. Large files will now be uploaded to Git LFS")
        return 0
    else:
        print("\n[ERROR] Installation verification failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
