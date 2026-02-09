#!/usr/bin/env python3
"""
Cleanup script to remove .git directories from sync cache.
This fixes the issue where old .git metadata prevents change detection.

Usage: python cleanup_cache_git.py
"""

import shutil
from pathlib import Path


def cleanup_cache_git_dirs():
    """Remove .git directories from all cache repositories."""
    cache_dir = Path.home() / ".repo_sync_gui" / "repo_cache"

    if not cache_dir.exists():
        print(f"[INFO] Cache directory does not exist: {cache_dir}")
        return

    print(f"[INFO] Scanning cache directory: {cache_dir}")

    removed_count = 0
    for git_dir in cache_dir.rglob(".git"):
        if git_dir.is_dir():
            try:
                print(f"[REMOVE] {git_dir}")
                shutil.rmtree(git_dir)
                removed_count += 1
            except Exception as e:
                print(f"[ERROR] Failed to remove {git_dir}: {e}")

    if removed_count == 0:
        print("[INFO] No .git directories found in cache.")
    else:
        print(f"[SUCCESS] Removed {removed_count} .git directory(ies).")
        print("[INFO] Please run the sync tool again to re-sync your files.")


if __name__ == "__main__":
    cleanup_cache_git_dirs()
