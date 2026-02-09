# Folder Sync Tool (PySide6)

A desktop GUI to sync folders between:

- a local repository folder,
- a repository URL,
- and Windows/local folders.

## Features

- PySide6 GUI.
- Sync pairs with **Source folder** and **Target folder**.
- Background worker execution using multiple threads (GUI stays responsive).
- Progress bar with live percentage and current operation text.
- Optional one-way or two-way sync.
- Optional stale-file cleanup on destination.
- Optional auto update checks.
- Optional **continuous watch mode** (checks permanently without using interval).
- Optional auto-sync on new commit/change.
- Repository URL watch mode tracks **`main` branch commits** (`refs/heads/main`).
- Optional **auto commit and push** after sync.
- Optional login with username/password for repository URLs.
- Optional encrypted credential storage.
- Persisted sync pair configuration across restarts.

## Requirements

- Python 3.10+
- PySide6
- Git

Install dependency:

```bash
pip install PySide6
```

## Run

```bash
python sync_gui.py
```

## Notes

- For URL repos with relative source/target paths, **Local repo workspace** is required (otherwise sync is blocked).
- If **Local repo workspace** is empty, a cache path under `~/.repo_sync_gui/repo_cache` is used.
- Auto-update on repository URLs checks `refs/heads/main`.
- If a new commit appears on `main`, auto-sync runs immediately (when enabled).
- Continuous watch mode ignores interval and checks continuously in short cycles.
- Auto commit/push uses the resolved local git repository (workspace path or cache clone).
