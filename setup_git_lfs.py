#!/usr/bin/env python3
"""
Setup Git LFS for repositories with large files.
This script configures Git LFS and migrates large files automatically.

Usage: python setup_git_lfs.py
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, cwd, description):
    """Run a command and return success status."""
    print(f"[RUN] {description}")
    print(f"      Command: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode != 0:
        print(f"[ERROR] {description} failed")
        print(f"STDERR: {result.stderr}")
        print(f"STDOUT: {result.stdout}")
        return False

    print(f"[SUCCESS] {description}")
    if result.stdout.strip():
        print(f"Output: {result.stdout.strip()}")
    return True


def setup_git_lfs_for_repo(repo_path):
    """Setup Git LFS for a repository."""
    repo_path = Path(repo_path)

    if not (repo_path / ".git").exists():
        print(f"[ERROR] Not a git repository: {repo_path}")
        return False

    print(f"\n[INFO] Setting up Git LFS for: {repo_path}")

    # Check if git-lfs is installed
    try:
        subprocess.run(
            ["git", "lfs", "version"],
            capture_output=True,
            check=True,
            timeout=10
        )
        print("[INFO] Git LFS is installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] Git LFS is not installed!")
        print("[INFO] Please install Git LFS from: https://git-lfs.github.com/")
        print("[INFO] Or run: git lfs install")
        return False

    # Install Git LFS hooks in the repository
    if not run_command(
        ["git", "lfs", "install"],
        repo_path,
        "Install Git LFS hooks"
    ):
        return False

    # Track large XML files with LFS
    patterns = [
        "*.xml",  # Track all XML files
        "*.dat",  # Track data files if any
        "*.bin",  # Track binary files if any
    ]

    for pattern in patterns:
        if not run_command(
            ["git", "lfs", "track", pattern],
            repo_path,
            f"Track {pattern} with Git LFS"
        ):
            return False

    # Add .gitattributes
    if not run_command(
        ["git", "add", ".gitattributes"],
        repo_path,
        "Add .gitattributes"
    ):
        return False

    # Check current status
    run_command(
        ["git", "lfs", "ls-files"],
        repo_path,
        "List LFS tracked files"
    )

    print("\n[SUCCESS] Git LFS setup complete!")
    print("[INFO] Next steps:")
    print("  1. The sync tool will now track large files with LFS")
    print("  2. Run the sync again to commit and push changes")
    print("  3. Large files will be uploaded to Git LFS storage")

    return True


def setup_lfs_for_cache():
    """Setup Git LFS for all cache repositories."""
    cache_dir = Path.home() / ".repo_sync_gui" / "repo_cache"

    if not cache_dir.exists():
        print(f"[INFO] Cache directory does not exist: {cache_dir}")
        return

    print(f"[INFO] Scanning cache directory: {cache_dir}")

    for repo_dir in cache_dir.iterdir():
        if repo_dir.is_dir() and (repo_dir / ".git").exists():
            setup_git_lfs_for_repo(repo_dir)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Setup LFS for specific repository
        repo_path = sys.argv[1]
        setup_git_lfs_for_repo(repo_path)
    else:
        # Setup LFS for all cache repositories
        setup_lfs_for_cache()
