# Folder Sync Tool (PySide6)

A desktop GUI to sync folders between:

- a local repository folder,
- a repository URL (cloned temporarily for sync),
- and Windows/local folders.

## Features

- PySide6 GUI.
- Sync pairs with **Source folder** and **Target folder**.
- Optional one-way or two-way sync.
- Optional stale-file cleanup on destination.
- Optional auto update checks.
- Optional **continuous watch mode** (checks permanently without using interval).
- Optional auto-sync on new commit/change.
- Repository URL watch mode tracks **`main` branch commits** (`refs/heads/main`).
- Optional **auto commit and push** after sync (for local git repo roots).
- Visible status indicator (`Idle`, `Watching...`, `Checking...`, `Auto-sync in progress...`).
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

- Auto-update on repository URLs checks `refs/heads/main` with `git ls-remote`.
- If a new commit appears on `main`, auto-sync runs immediately (when enabled).
- Continuous watch mode ignores interval and checks continuously in short cycles.
- Auto commit/push works only when **Repo root** is a local git repository path.
- If repo input is a URL, it uses a temporary clone and auto-push is skipped.
