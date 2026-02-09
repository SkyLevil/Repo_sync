from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlsplit, urlunsplit


class RepoResolver:
    def __init__(self, logger: Callable[[str], None], cache_dir: Optional[Path] = None):
        self._logger = logger
        self._cache_dir = cache_dir or (Path.home() / ".repo_sync_gui" / "repo_cache")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

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
            return self._ensure_local_clone(repo_input, username=username, password=password)

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
        repo_path = self._ensure_local_clone(repo_url, username=username, password=password)
        self._update_clone(repo_path)
        process = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", f"origin/{branch}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to resolve origin/{branch}.\n{process.stderr.strip() or process.stdout.strip()}")
        return process.stdout.strip()

    def _ensure_local_clone(self, repo_url: str, username: str = "", password: str = "") -> Path:
        auth_url = self._build_authenticated_url(repo_url, username, password)
        clone_target = self._cache_dir / self._url_hash(repo_url)

        if (clone_target / ".git").exists():
            self._update_clone(clone_target)
            return clone_target

        self._logger(f"[INFO] Creating local cached clone: {repo_url}")
        process = subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, str(clone_target)],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to clone repository URL.\n{process.stderr.strip()}")

        self._logger(f"[INFO] Repository cached at: {clone_target}")
        return clone_target

    def _update_clone(self, repo_path: Path) -> None:
        process = subprocess.run(
            ["git", "-C", str(repo_path), "fetch", "--depth", "1", "origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to update cached repository.\n{process.stderr.strip() or process.stdout.strip()}")

    @staticmethod
    def _url_hash(value: str) -> str:
        return hashlib.sha1(value.encode("utf-8")).hexdigest()[:16]

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
        # persistent cache mode: nothing to clean up
        return
