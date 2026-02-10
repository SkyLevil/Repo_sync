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
- Persistent crash debug log written to `~/.repo_sync_gui/crash.log` (including unhandled exceptions and low-level fault dumps).
- Early-start bootstrap log written to `~/.repo_sync_gui/bootstrap_crash.log` to diagnose crashes before the UI is shown.

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
- Sync logs show the local clone path for repository URLs, but the clone is refreshed from the remote repository before each run.
- If the internal cache path is corrupted or no longer a valid git repository, it is recreated automatically.
- Repository URL checks and sync refreshes are serialized per cached repository path to avoid concurrent fetch/update conflicts.
- Repository URL sources are refreshed from `origin` and the local working tree is aligned to the remote default branch before sync.
- The source/target selection now happens per row via endpoint type dropdowns.
- Path picker buttons work only for rows where endpoint type is `Path`.
- File comparison uses content hashing (SHA-256), not only timestamps, so changed files with same size are detected reliably.
- During automatic sync runs, stale files are removed on the target side to keep source/target states aligned.

- Git metadata folders (`.git`) are excluded from file-sync operations to avoid corrupting repository internals.

- Auto commit/push will create a commit each sync run (`--allow-empty`) so pushes are always visible on GitHub.

- Repository targets are reset to `origin/<push-branch>` before each sync run to avoid stale local commits in cached clones.
- If the configured push branch does not exist with exact casing on `origin`, the app resolves a matching remote branch (case-insensitive) or falls back to the remote default branch as sync base.
- Files larger than 95 MB are automatically tracked with Git LFS before commit/push.
- Git LFS must be installed locally for >95MB files (`git lfs version`).
- After pushing, the app also runs an explicit `git lfs push origin <branch>` for large files to ensure LFS objects are uploaded.
- On GitHub, LFS-tracked files can appear as a small text pointer in the file viewer; this is expected. Use `git lfs ls-files` locally to verify the large binary is tracked/uploaded.
