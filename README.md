# Folder Sync Tool (PySide6)

A desktop GUI to sync folders between:

- a local repository folder,
- a repository URL (cloned temporarily),
- and Windows/local folders.

## Features

- PySide6 GUI.
- Sync pairs with **Source folder** and **Target folder**.
- Supports:
  - repo-link-folder -> Windows folder
  - Windows folder -> Windows folder
  - local repo folder -> Windows folder
- Optional one-way or two-way sync.
- Optional stale-file cleanup on destination.
- Detailed in-app log.

## Requirements

- Python 3.10+
- PySide6
- Git (required when using a repository URL)

Install dependency:

```bash
pip install PySide6
```

## Run

```bash
python sync_gui.py
```

## Usage

1. (Optional) Enter **Repo root / Repo URL**:
   - local path, e.g. `C:\projects\myrepo`
   - URL, e.g. `https://github.com/org/repo.git`
2. Add sync pairs:
   - **Source folder**
   - **Target folder**
3. Path rules:
   - Absolute path: used directly (good for Windows/Windows sync)
   - Relative path: resolved against repo root/URL clone
4. Optional settings:
   - **Two-way sync**
   - **Delete stale files on destination**
5. Click **Run sync**.

## Notes

- If repo input is a URL, the repo is cloned to a temporary folder for the sync run.
- Relative source/target paths require a repo root or repo URL.
- Target folders are created automatically when missing.
