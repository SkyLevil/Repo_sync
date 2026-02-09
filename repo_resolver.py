from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlsplit, urlunsplit


class RepoResolver:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger
        self._temp_dir: Optional[tempfile.TemporaryDirectory[str]] = None

    @staticmethod
    def is_repo_url(value: str) -> bool:
        value_lower = value.lower().strip()
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

        if self.is_repo_url(repo_input):
            return self._clone_repo(repo_input, username=username, password=password)

        repo_path = Path(repo_input)
        if not repo_path.exists() or not repo_path.is_dir():
            raise ValueError("Repo root path does not exist or is not a folder.")

        return repo_path

    def get_remote_branch_head(
        self,
        repo_url: str,
        branch: str = "main",
        username: str = "",
        password: str = "",
    ) -> str:
        auth_url = self._build_authenticated_url(repo_url, username, password)
        ref = f"refs/heads/{branch}"
        process = subprocess.run(
            ["git", "ls-remote", auth_url, ref],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to query remote branch '{branch}'.\n{process.stderr.strip()}")

        line = process.stdout.strip().splitlines()[0] if process.stdout.strip() else ""
        if not line:
            raise ValueError(f"Remote branch '{branch}' was not found.")
        return line.split()[0]

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
            timeout=120,
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

        parsed = urlsplit(repo_url)
        if not parsed.hostname:
            return repo_url

        quoted_user = quote(username, safe="")
        quoted_pass = quote(password, safe="")

        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        netloc = f"{quoted_user}:{quoted_pass}@{host}"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    def cleanup(self) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None
