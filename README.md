# Repo ↔ Windows Folder Sync Tool (PySide6)

This project provides a simple desktop GUI to sync folders from a repository to folders on a Windows system.

## Features

- PySide6 GUI.
- Map one or more repo subfolders to Windows target folders.
- One-way sync (`repo -> windows`) or optional two-way sync.
- Optional stale-file cleanup on destination.
- Detailed sync log in the UI.

## Requirements

- Python 3.10+
- PySide6

Install dependency:

```bash
pip install PySide6
```

## Run

```bash
python sync_gui.py
```

## Usage

1. Select the repository root.
2. Add mapping rows:
   - **Repo subfolder**: relative path (for example `assets/images`)
   - **Windows target folder**: absolute path on the Windows system
3. (Optional) Enable:
   - **Two-way sync**
   - **Delete stale files on destination**
4. Click **Run sync**.

## Notes

- Repo subfolder paths must be relative (not absolute).
- Target folders are created automatically when missing.
- If you use two-way sync + stale deletion, review your mappings carefully.
