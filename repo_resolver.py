from __future__ import annotations

import hashlib
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlsplit, urlunsplit


class RepoResolver:
    _lock_map: dict[str, threading.Lock] = {}
    _lock_map_guard = threading.Lock()

    def __init__(self, logger: Callable[[str], None], cache_dir: Optional[Path] = None):
        self._logger = logger
        self._cache_dir = cache_dir or (Path.home() / ".repo_sync_gui" / "repo_cache")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _repo_lock(cls, repo_path: Path) -> threading.Lock:
        key = str(repo_path.resolve())
        with cls._lock_map_guard:
            lock = cls._lock_map.get(key)
            if lock is None:
                lock = threading.Lock()
                cls._lock_map[key] = lock
            return lock

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

    def resolve(
        self,
        repo_input: str,
        username: str = "",
        password: str = "",
        local_repo_path: str = "",
    ) -> Optional[Path]:
        repo_input = repo_input.strip()
        if not repo_input:
            return None

        if self.is_repo_url(repo_input):
            return self._ensure_local_clone(
                repo_input,
                username=username,
                password=password,
                local_repo_path=local_repo_path,
            )

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
        local_repo_path: str = "",
    ) -> str:
        repo_path = self._ensure_local_clone(
            repo_url,
            username=username,
            password=password,
            local_repo_path=local_repo_path,
        )
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

    def _ensure_local_clone(
        self,
        repo_url: str,
        username: str = "",
        password: str = "",
        local_repo_path: str = "",
    ) -> Path:
        auth_url = self._build_authenticated_url(repo_url, username, password)
        clone_target = self._resolve_clone_target(repo_url, local_repo_path)
        has_user_local_path = bool(local_repo_path.strip())

        with self._repo_lock(clone_target):
            if clone_target.exists() and self._is_valid_git_repo(clone_target):
                self._update_clone(clone_target)
                if not self._has_non_git_files(clone_target):
                    self._logger(
                        "[WARN] Cached repository clone contains no working-tree files. Re-creating clone..."
                    )
                    self._recreate_clone(clone_target, auth_url)
                return clone_target

            if clone_target.exists() and any(clone_target.iterdir()):
                if not has_user_local_path:
                    self._logger(
                        "[WARN] Cached repository path exists but is not a valid git repository. Re-creating clone..."
                    )
                    self._recreate_clone(clone_target, auth_url)
                    return clone_target
                raise ValueError(
                    f"Local repo path exists and is not a git repo: {clone_target}. "
                    "Please choose an empty folder or an existing git clone."
                )
            clone_target.parent.mkdir(parents=True, exist_ok=True)

            self._logger(f"[INFO] Creating local clone: {repo_url} -> {clone_target}")
            process = subprocess.run(
                ["git", "clone", "--depth", "1", auth_url, str(clone_target)],
                capture_output=True,
                text=True,
                check=False,
                timeout=180,
            )
            if process.returncode != 0:
                raise ValueError(f"Failed to clone repository URL.\n{process.stderr.strip()}")

            self._logger(f"[INFO] Repository ready at: {clone_target}")
            return clone_target

    @staticmethod
    def _is_valid_git_repo(repo_path: Path) -> bool:
        if not repo_path.exists() or not repo_path.is_dir():
            return False

        process = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return process.returncode == 0 and process.stdout.strip().lower() == "true"

    @staticmethod
    def _has_non_git_files(repo_path: Path) -> bool:
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(repo_path)
            except ValueError:
                continue
            if ".git" in rel.parts:
                continue
            return True
        return False

    def _recreate_clone(self, clone_target: Path, auth_url: str) -> None:
        self._remove_path_tree(clone_target)
        clone_target.parent.mkdir(parents=True, exist_ok=True)

        process = subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, str(clone_target)],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to recreate cached clone.\n{process.stderr.strip() or process.stdout.strip()}")

        if not self._has_non_git_files(clone_target):
            raise ValueError(
                "Repository clone does not contain working-tree files after refresh. "
                f"Please verify repository content and permissions for: {auth_url}"
            )

    @staticmethod
    def _remove_path_tree(path: Path) -> None:
        if not path.exists():
            return

        def _onerror(func, target, exc_info):
            _ = exc_info
            try:
                Path(target).chmod(0o700)
            except OSError:
                pass
            func(target)

        shutil.rmtree(path, onerror=_onerror)
        if path.exists():
            raise ValueError(f"Failed to remove stale cache path: {path}")

    def _resolve_clone_target(self, repo_url: str, local_repo_path: str) -> Path:
        if local_repo_path.strip():
            return Path(local_repo_path.strip())
        return self._cache_dir / self._url_hash(repo_url)

    def _update_clone(self, repo_path: Path) -> None:
        process = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "fetch",
                "--depth",
                "1",
                "--prune",
                "--force",
                "origin",
                "+refs/heads/*:refs/remotes/origin/*",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if process.returncode != 0:
            raise ValueError(f"Failed to update local repository.\n{process.stderr.strip() or process.stdout.strip()}")

        remote_default_branch = self._get_remote_default_branch(repo_path)
        self._checkout_remote_branch(repo_path, remote_default_branch)

    @staticmethod
    def _get_remote_default_branch(repo_path: Path) -> str:
        process = subprocess.run(
            ["git", "-C", str(repo_path), "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if process.returncode == 0 and process.stdout.strip().startswith("origin/"):
            return process.stdout.strip().split("/", 1)[1]

        branches = RepoResolver._list_remote_branches(repo_path)
        if "main" in branches:
            return "main"
        if "master" in branches:
            return "master"
        if branches:
            return branches[0]
        raise ValueError("No remote branches found on origin.")

    @staticmethod
    def _list_remote_branches(repo_path: Path) -> list[str]:
        output = subprocess.run(
            ["git", "-C", str(repo_path), "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if output.returncode != 0:
            raise ValueError(f"Failed to list origin branches.\n{output.stderr.strip() or output.stdout.strip()}")

        branches: list[str] = []
        for line in output.stdout.splitlines():
            ref = line.strip()
            if not ref.startswith("origin/"):
                continue
            name = ref.split("/", 1)[1]
            if name == "HEAD":
                continue
            branches.append(name)
        return branches

    @staticmethod
    def _checkout_remote_branch(repo_path: Path, branch: str) -> None:
        checkout = subprocess.run(
            ["git", "-C", str(repo_path), "checkout", "-B", branch, f"origin/{branch}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if checkout.returncode != 0:
            raise ValueError(
                f"Failed to checkout origin/{branch}.\n{checkout.stderr.strip() or checkout.stdout.strip()}"
            )

        reset = subprocess.run(
            ["git", "-C", str(repo_path), "reset", "--hard", f"origin/{branch}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if reset.returncode != 0:
            raise ValueError(
                f"Failed to reset local clone to origin/{branch}.\n{reset.stderr.strip() or reset.stdout.strip()}"
            )

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
        return
