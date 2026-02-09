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

        self._ensure_branch(repo_path, branch)
        self._run(["git", "-C", str(repo_path), "add", "-A"], "Stage changes")

        status = self._run_capture(["git", "-C", str(repo_path), "status", "--porcelain"], "Read status")
        if status.stdout.strip():
            self._logger("[INFO] Detected working tree changes; creating commit.")
        else:
            self._logger("[INFO] No file changes detected; creating empty sync commit.")

        commit = subprocess.run(
            ["git", "-C", str(repo_path), "commit", "--allow-empty", "-m", commit_message],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if commit.returncode != 0:
            raise ValueError(f"Git commit failed.\n{commit.stderr.strip() or commit.stdout.strip()}")

        self._logger("[INFO] Git commit created.")
        self._run(["git", "-C", str(repo_path), "push", "-u", "origin", branch], f"Push to origin/{branch}")
        self._logger(f"[INFO] Git push completed to origin/{branch}.")
        return True

    def _ensure_branch(self, repo_path: Path, branch: str) -> None:
        # Create/switch to branch locally so push target is explicit and stable.
        checkout = subprocess.run(
            ["git", "-C", str(repo_path), "checkout", branch],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if checkout.returncode == 0:
            return

        self._run(["git", "-C", str(repo_path), "checkout", "-B", branch], f"Create local branch {branch}")

    def _run(self, cmd: list[str], action: str) -> None:
        result = self._run_capture(cmd, action)
        if result.returncode != 0:
            raise ValueError(f"{action} failed.\n{result.stderr.strip() or result.stdout.strip()}")

    @staticmethod
    def _run_capture(cmd: list[str], action: str) -> subprocess.CompletedProcess[str]:
        _ = action
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
