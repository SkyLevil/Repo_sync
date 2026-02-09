from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Optional


class RepoResolver:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger
        self._temp_dir: Optional[tempfile.TemporaryDirectory[str]] = None

    @staticmethod
    def _looks_like_url(value: str) -> bool:
        value_lower = value.lower()
        return (
            value_lower.startswith("http://")
            or value_lower.startswith("https://")
            or value_lower.startswith("ssh://")
            or value_lower.startswith("git@")
            or value_lower.endswith(".git")
        )

    def resolve(self, repo_input: str, username: str = "", password: str = "") -> Optional[Path]:
        repo_input = repo_input.strip()
        if not repo_input:
            return None

        if self._looks_like_url(repo_input):
            return self._clone_repo(repo_input, username=username, password=password)

        repo_path = Path(repo_input)
        if not repo_path.exists() or not repo_path.is_dir():
            raise ValueError("Repo root path does not exist or is not a folder.")

        return repo_path

    def _clone_repo(self, repo_url: str, username: str = "", password: str = "") -> Path:
        self.cleanup()
        self._temp_dir = tempfile.TemporaryDirectory(prefix="repo_sync_")
        clone_target = Path(self._temp_dir.name) / "repo"

        auth_url = self._build_authenticated_url(repo_url, username, password)

        self._logger(f"[INFO] Cloning repository: {repo_url}")
        process = subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, str(clone_target)],
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode != 0:
            self.cleanup()
            raise ValueError(f"Failed to clone repository URL.\n{process.stderr.strip()}")

        self._logger(f"[INFO] Repository cloned to temporary path: {clone_target}")
        return clone_target

    @staticmethod
    def _build_authenticated_url(repo_url: str, username: str, password: str) -> str:
        if not username or not password:
            return repo_url
        if not repo_url.startswith("http://") and not repo_url.startswith("https://"):
            return repo_url

        scheme, rest = repo_url.split("://", maxsplit=1)
        return f"{scheme}://{username}:{password}@{rest}"

    def cleanup(self) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None
