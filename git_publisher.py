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

        self._run(["git", "-C", str(repo_path), "fetch", "--prune", "origin"], "Fetch origin")

        remote_branch = self._resolve_remote_branch(repo_path, branch)
        if remote_branch is None:
            remote_branch = self._get_remote_default_branch(repo_path)
            self._logger(
                f"[WARN] origin/{branch} not found. Using origin/{remote_branch} as preparation base."
            )

        if remote_branch.lower() != branch.lower():
            self._logger(f"[INFO] Using remote branch origin/{remote_branch} for configured branch '{branch}'.")

        self._run(
            ["git", "-C", str(repo_path), "checkout", "-B", branch, f"origin/{remote_branch}"],
            f"Checkout {branch} from origin/{remote_branch}",
        )
        self._run(["git", "-C", str(repo_path), "reset", "--hard", f"origin/{remote_branch}"], "Reset local branch")
        self._run(["git", "-C", str(repo_path), "clean", "-fd"], "Clean untracked files")
        self._logger(f"[INFO] Repository prepared at {repo_path} on branch {branch}.")

    def commit_and_push(self, repo_path: Path, branch: str, commit_message: str) -> bool:
        if not (repo_path / ".git").exists():
            raise ValueError(f"'{repo_path}' is not a git repository (missing .git).")

        self._ensure_branch(repo_path, branch)
        lfs_touched = self._track_large_files_with_lfs(repo_path)
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
        self._run(["git", "-C", str(repo_path), "push", "-u", "origin", branch], f"Push commit to origin/{branch}")

        if lfs_touched:
            self._logger("[INFO] Uploading Git LFS objects...")
            self._run(["git", "-C", str(repo_path), "lfs", "push", "origin", branch], f"Push LFS objects to origin/{branch}")
            lfs_list = self._run_capture(["git", "-C", str(repo_path), "lfs", "ls-files"], "List LFS files")
            if lfs_list.stdout.strip():
                self._logger("[INFO] LFS tracked files:\n" + lfs_list.stdout.strip())
            self._logger(
                "[INFO] Large files are stored in Git LFS. GitHub file view may show a small pointer text file."
            )

        self._logger(f"[INFO] Git push completed to origin/{branch}.")
        return True

    def _track_large_files_with_lfs(self, repo_path: Path) -> bool:
        large_files = self._find_large_files(repo_path)
        if not large_files:
            return False

        self._ensure_git_lfs_available(repo_path)
        self._run(["git", "-C", str(repo_path), "lfs", "install", "--local"], "Initialize Git LFS")

        for rel in large_files:
            self._logger(f"[INFO] Tracking large file with Git LFS: {rel}")
            self._run(["git", "-C", str(repo_path), "lfs", "track", "--", rel], f"Track LFS file {rel}")

        self._run(["git", "-C", str(repo_path), "add", ".gitattributes"], "Stage .gitattributes")
        return True

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

    def _resolve_remote_branch(self, repo_path: Path, branch: str) -> str | None:
        branch_names = self._list_remote_branches(repo_path)
        if branch in branch_names:
            return branch

        wanted = branch.lower()
        for remote_branch in branch_names:
            if remote_branch.lower() == wanted:
                return remote_branch

        return None

    def _get_remote_default_branch(self, repo_path: Path) -> str:
        head = self._run_capture(
            ["git", "-C", str(repo_path), "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            "Resolve origin/HEAD",
        )
        if head.returncode == 0 and head.stdout.strip().startswith("origin/"):
            return head.stdout.strip().split("/", 1)[1]

        branches = self._list_remote_branches(repo_path)
        if "main" in branches:
            return "main"
        if "master" in branches:
            return "master"
        if branches:
            return branches[0]
        raise ValueError("No remote branches found on origin.")

    def _list_remote_branches(self, repo_path: Path) -> list[str]:
        output = self._run_capture(
            ["git", "-C", str(repo_path), "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
            "List origin branches",
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
