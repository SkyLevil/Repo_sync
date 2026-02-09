# Folder Sync Tool (PySide6)

A desktop GUI to sync folders between:

- a local repository folder,
- a repository URL (cloned temporarily for sync),
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
- Visible status indicator (`Idle`, `Watching for changes...`, `Checking for changes...`, `Auto-sync in progress...`).
- Optional login with username/password for repository URLs.
- Optional encrypted credential storage.
- Persisted sync pair configuration across restarts.

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

## Notes

- Periodic checks for repository URLs use `git ls-remote` to detect remote HEAD changes.
- Auto-sync runs only when a change is detected and the auto-sync checkbox is enabled.
- If repo input is a URL, the repo is cloned to a temporary folder for sync execution.
- Relative source/target paths require a repo root or repo URL.
- Target folders are created automatically when missing.
- Sync pairs and options are stored with QSettings.
- Encrypted credentials are stored with a local key in `~/.repo_sync_gui/secret.key`.
- The code is split across modules for readability (`main_window.py`, `repo_resolver.py`, `sync_engine.py`, `credential_store.py`, `sync_models.py`).
