from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, List

LFS_THRESHOLD_BYTES = 95 * 1024 * 1024


class GitPublisher:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger

    def prepare_repository(self, repo_path: Path, branch: str) -> None:
        if not (repo_path / ".git").exists():
            raise ValueError(f"'{repo_path}' is not a git repository (missing .git).")

        self._ensure_branch(repo_path, branch)
        self._run(["git", "-C", str(repo_path), "fetch", "origin", branch], f"Fetch origin/{branch}")
        self._run(["git", "-C", str(repo_path), "reset", "--hard", f"origin/{branch}"], "Reset local branch")
        self._run(["git", "-C", str(repo_path), "clean", "-fd"], "Clean untracked files")
        self._logger(f"[INFO] Repository prepared at {repo_path} on branch {branch}.")

    def commit_and_push(self, repo_path: Path, branch: str, commit_message: str) -> bool:
        if not (repo_path / ".git").exists():
            raise ValueError(f"'{repo_path}' is not a git repository (missing .git).")

        self._ensure_branch(repo_path, branch)
        self._track_large_files_with_lfs(repo_path)
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

    def _track_large_files_with_lfs(self, repo_path: Path) -> None:
        large_files = self._find_large_files(repo_path)
        if not large_files:
            return

        self._ensure_git_lfs_available(repo_path)
        self._run(["git", "-C", str(repo_path), "lfs", "install", "--local"], "Initialize Git LFS")

        for rel in large_files:
            self._logger(f"[INFO] Tracking large file with Git LFS: {rel}")
            self._run(["git", "-C", str(repo_path), "lfs", "track", "--", rel], f"Track LFS file {rel}")

        # ensure .gitattributes is staged if updated by lfs track
        self._run(["git", "-C", str(repo_path), "add", ".gitattributes"], "Stage .gitattributes")

    def _find_large_files(self, repo_path: Path) -> List[str]:
        files: List[str] = []
        for p in repo_path.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(repo_path)
            if ".git" in rel.parts:
                continue
            try:
                if p.stat().st_size > LFS_THRESHOLD_BYTES:
                    files.append(rel.as_posix())
            except OSError:
                continue
        return files

    def _ensure_git_lfs_available(self, repo_path: Path) -> None:
        check = self._run_capture(["git", "-C", str(repo_path), "lfs", "version"], "Check Git LFS")
        if check.returncode != 0:
            raise ValueError(
                "Git LFS is required for files larger than 95MB. "
                "Please install Git LFS (https://git-lfs.github.com/) and retry."
            )

    def _ensure_branch(self, repo_path: Path, branch: str) -> None:
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
