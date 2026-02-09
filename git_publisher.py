from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable


class GitPublisher:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger

    def commit_and_push(self, repo_path: Path, branch: str, commit_message: str) -> bool:
        if not (repo_path / ".git").exists():
            raise ValueError(f"'{repo_path}' is not a git repository (missing .git).")

        self._run(["git", "-C", str(repo_path), "add", "-A"], "Stage changes")

        status = self._run_capture(["git", "-C", str(repo_path), "status", "--porcelain"], "Read status")
        if not status.stdout.strip():
            self._logger("[INFO] Git push skipped: no changes to commit.")
            return True

        commit = subprocess.run(
            ["git", "-C", str(repo_path), "commit", "-m", commit_message],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if commit.returncode != 0:
            raise ValueError(f"Git commit failed.\n{commit.stderr.strip() or commit.stdout.strip()}")

        self._logger("[INFO] Git commit created.")
        self._run(["git", "-C", str(repo_path), "push", "origin", branch], f"Push to origin/{branch}")
        self._logger(f"[INFO] Git push completed to origin/{branch}.")
        return True

    def _run(self, cmd: list[str], action: str) -> None:
        result = self._run_capture(cmd, action)
        if result.returncode != 0:
            raise ValueError(f"{action} failed.\n{result.stderr.strip() or result.stdout.strip()}")

    @staticmethod
    def _run_capture(cmd: list[str], action: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
