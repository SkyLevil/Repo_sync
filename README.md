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
- Optional periodic change checks.
- Optional auto-sync when source changes are detected.
- Optional login with username/password for repository URLs.
- Optional encrypted credential storage.
- Persisted sync pair configuration across restarts.

## Requirements

- Python 3.10+
- PySide6
- cryptography
- Git (required when using a repository URL)

Install dependencies:

```bash
pip install PySide6 cryptography
```

## Run

```bash
python sync_gui.py
```

## Usage

1. (Optional) Enter **Repo root / Repo URL**:
   - local path, e.g. `C:\projects\myrepo`
   - URL, e.g. `https://github.com/org/repo.git`
2. (Optional) Enter repository **Username** and **Password/Token**.
3. Enable **Save credentials encrypted** if credentials should persist.
4. Add sync pairs:
   - **Source folder**
   - **Target folder**
5. Path rules:
   - Absolute path: used directly (good for Windows/Windows sync)
   - Relative path: resolved against repo root/URL clone
6. Optional settings:
   - **Two-way sync**
   - **Delete stale files on destination**
   - **Enable periodic change checks** + interval
   - **Auto sync when changes are detected**
7. Click **Run sync now**.

## Notes

- If repo input is a URL, the repo is cloned to a temporary folder for each sync/check run.
- Relative source/target paths require a repo root or repo URL.
- Target folders are created automatically when missing.
- Sync pairs and options are stored with QSettings.
- Encrypted credentials are stored with a local key in `~/.repo_sync_gui/secret.key`.
