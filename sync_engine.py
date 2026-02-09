from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, List, Optional

from sync_models import SyncPair

ProgressCallback = Callable[[int, int, str], None]
MAX_SYNC_FILE_BYTES = 95 * 1024 * 1024


class SyncEngine:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger

    @staticmethod
    def _is_git_metadata(relative_path: Path) -> bool:
        return ".git" in relative_path.parts

    def count_total_work_items(self, pairs: List[SyncPair], two_way: bool, delete_stale: bool) -> int:
        total = 0
        for pair in pairs:
            total += self._count_one_way(pair.source, pair.target, delete_stale)
            if two_way:
                total += self._count_one_way(pair.target, pair.source, delete_stale)
        return max(total, 1)

    def _count_one_way(self, source: Path, target: Path, delete_stale: bool) -> int:
        if not source.exists() or not source.is_dir():
            return 1

        src_files = 0
        for p in source.rglob("*"):
            if not p.is_file() or self._is_git_metadata(p.relative_to(source)):
                continue
            try:
                if p.stat().st_size > MAX_SYNC_FILE_BYTES:
                    continue
            except OSError:
                continue
            src_files += 1
        dst_files = 0
        if delete_stale and target.exists() and target.is_dir():
            for p in target.rglob("*"):
                if not p.is_file() or self._is_git_metadata(p.relative_to(target)):
                    continue
                try:
                    if p.stat().st_size > MAX_SYNC_FILE_BYTES:
                        continue
                except OSError:
                    continue
                dst_files += 1
        return max(src_files + dst_files, 1)

    def sync_pairs(
        self,
        pairs: List[SyncPair],
        two_way: bool,
        delete_stale: bool,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        total = self.count_total_work_items(pairs, two_way=two_way, delete_stale=delete_stale)
        progress = {"done": 0, "total": total}

        for pair in pairs:
            source = pair.source
            target = pair.target

            if not source.exists() or not source.is_dir():
                self._logger(f"[SKIP] Source folder does not exist: {source}")
                self._emit_progress(progress_callback, progress, f"Skipped missing source: {source}")
                continue

            if not target.exists():
                self._logger(f"[INFO] Creating target folder: {target}")
                target.mkdir(parents=True, exist_ok=True)

            self._logger(f"[SYNC] {source} -> {target}")
            self._sync_one_way(source, target, delete_stale, progress_callback, progress)

            if two_way:
                self._logger(f"[SYNC] {target} -> {source}")
                self._sync_one_way(target, source, delete_stale, progress_callback, progress)

        if progress_callback:
            progress_callback(progress["total"], progress["total"], "Sync completed")

    def _sync_one_way(
        self,
        source: Path,
        target: Path,
        delete_stale: bool,
        progress_callback: Optional[ProgressCallback],
        progress: dict,
    ) -> None:
        copied, updated, skipped = 0, 0, 0

        for src_file in source.rglob("*"):
            if src_file.is_dir():
                continue

            relative = src_file.relative_to(source)
            if self._is_git_metadata(relative):
                continue

            try:
                src_size = src_file.stat().st_size
            except OSError:
                self._emit_progress(progress_callback, progress, f"Skipped unreadable {relative}")
                continue

            if src_size > MAX_SYNC_FILE_BYTES:
                self._logger(
                    f"  ! skipped large file (>95MB, use Git LFS): {relative} ({src_size} bytes)"
                )
                self._emit_progress(progress_callback, progress, f"Skipped large {relative}")
                continue

            dst_file = target / relative
            dst_file.parent.mkdir(parents=True, exist_ok=True)

            if not dst_file.exists():
                shutil.copy2(src_file, dst_file)
                copied += 1
                self._logger(f"  + copied: {relative}")
                self._emit_progress(progress_callback, progress, f"Copied {relative}")
                continue

            src_stat = src_file.stat()
            dst_stat = dst_file.stat()

            if src_stat.st_mtime > dst_stat.st_mtime or src_stat.st_size != dst_stat.st_size:
                shutil.copy2(src_file, dst_file)
                updated += 1
                self._logger(f"  * updated: {relative}")
                self._emit_progress(progress_callback, progress, f"Updated {relative}")
            else:
                skipped += 1
                self._emit_progress(progress_callback, progress, f"Checked {relative}")

        removed = 0
        if delete_stale:
            for dst_file in target.rglob("*"):
                if dst_file.is_dir():
                    continue

                relative = dst_file.relative_to(target)
                if self._is_git_metadata(relative):
                    continue

                src_file = source / relative
                if not src_file.exists():
                    dst_file.unlink()
                    removed += 1
                    self._logger(f"  - removed stale file: {relative}")
                    self._emit_progress(progress_callback, progress, f"Removed stale {relative}")
                else:
                    self._emit_progress(progress_callback, progress, f"Validated {relative}")

        self._logger(
            f"[DONE] copied={copied}, updated={updated}, skipped={skipped}, removed={removed}"
        )

    @staticmethod
    def _emit_progress(progress_callback: Optional[ProgressCallback], progress: dict, message: str) -> None:
        progress["done"] += 1
        if progress_callback:
            progress_callback(progress["done"], progress["total"], message)
