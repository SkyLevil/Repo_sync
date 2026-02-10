# Folder Sync Tool (PySide6)

A desktop GUI to sync directly between local folders and remote repositories.

## Features

- Pair table with explicit endpoint types:
  - **Path**
  - **Repository URL**
- Sync from local folder -> remote repository or remote repository -> local folder.
- Background worker execution using multiple threads (GUI stays responsive).
- Progress bar with live percentage and current operation text.
- Optional one-way or two-way sync.
- Optional stale-file cleanup on destination.
- Optional auto update checks and continuous watch mode.
- Optional auto-sync on detected source change.
- Optional auto commit/push for repository targets.
- Optional login with username/password for repository URLs.
- Persisted settings and sync table across restarts.

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

- For `Repository URL` entries, the app resolves and maintains a local clone internally.
- The source/target selection now happens per row via endpoint type dropdowns.
- Path picker buttons work only for rows where endpoint type is `Path`.

- Git metadata folders (`.git`) are excluded from file-sync operations to avoid corrupting repository internals.

- Auto commit/push will create a commit each sync run (`--allow-empty`) so pushes are always visible on GitHub.

- Repository targets are reset to `origin/<push-branch>` before each sync run to avoid stale local commits in cached clones.
- Files larger than 95 MB are automatically tracked with Git LFS before commit/push.
- Git LFS must be installed locally for >95MB files (`git lfs version`).
