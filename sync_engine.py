from __future__ import annotations

import hashlib
import logging
import shutil
import traceback
from pathlib import Path
from typing import Callable, List, Optional

from sync_models import SyncPair

ProgressCallback = Callable[[int, int, str], None]

_log = logging.getLogger("repo_sync_gui.sync_engine")


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

        try:
            src_files = sum(
                1 for p in source.rglob("*") if p.is_file() and not self._is_git_metadata(p.relative_to(source))
            )
        except OSError as exc:
            _log.warning("Error counting source files in %s: %s", source, exc)
            src_files = 0

        dst_files = 0
        if delete_stale and target.exists() and target.is_dir():
            try:
                dst_files = sum(
                    1 for p in target.rglob("*") if p.is_file() and not self._is_git_metadata(p.relative_to(target))
                )
            except OSError as exc:
                _log.warning("Error counting target files in %s: %s", target, exc)
        return max(src_files + dst_files, 1)

    def sync_pairs(
        self,
        pairs: List[SyncPair],
        two_way: bool,
        delete_stale: bool,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        _log.info("sync_pairs called: %d pair(s), two_way=%s, delete_stale=%s", len(pairs), two_way, delete_stale)
        total = self.count_total_work_items(pairs, two_way=two_way, delete_stale=delete_stale)
        progress = {"done": 0, "total": total}

        for pair in pairs:
            source = pair.source
            target = pair.target

            if not source.exists() or not source.is_dir():
                self._logger(f"[SKIP] Source folder does not exist: {source}")
                _log.warning("Skipping missing source: %s", source)
                self._emit_progress(progress_callback, progress, f"Skipped missing source: {source}")
                continue

            if not target.exists():
                self._logger(f"[INFO] Creating target folder: {target}")
                _log.info("Creating target folder: %s", target)
                try:
                    target.mkdir(parents=True, exist_ok=True)
                except OSError as exc:
                    self._logger(f"[ERROR] Cannot create target folder {target}: {exc}")
                    _log.error("Cannot create target folder %s: %s", target, exc)
                    continue

            self._logger(f"[SYNC] {source} -> {target}")
            _log.info("Syncing %s -> %s", source, target)
            try:
                self._sync_one_way(source, target, delete_stale, progress_callback, progress)
            except Exception as exc:  # noqa: BLE001
                self._logger(f"[ERROR] Sync failed ({source} -> {target}): {exc}")
                _log.error("Sync one-way failed (%s -> %s):\n%s", source, target, traceback.format_exc())

            if two_way:
                self._logger(f"[SYNC] {target} -> {source}")
                _log.info("Syncing (reverse) %s -> %s", target, source)
                try:
                    self._sync_one_way(target, source, delete_stale, progress_callback, progress)
                except Exception as exc:  # noqa: BLE001
                    self._logger(f"[ERROR] Reverse sync failed ({target} -> {source}): {exc}")
                    _log.error("Reverse sync failed (%s -> %s):\n%s", target, source, traceback.format_exc())

        if progress_callback:
            progress_callback(progress["total"], progress["total"], "Sync completed")
        _log.info("sync_pairs finished")

    def _sync_one_way(
        self,
        source: Path,
        target: Path,
        delete_stale: bool,
        progress_callback: Optional[ProgressCallback],
        progress: dict,
    ) -> None:
        copied, updated, skipped = 0, 0, 0

        source_files = [
            p for p in source.rglob("*") if p.is_file() and not self._is_git_metadata(p.relative_to(source))
        ]

        for src_file in source_files:
            relative = src_file.relative_to(source)
            dst_file = target / relative

            try:
                dst_file.parent.mkdir(parents=True, exist_ok=True)

                if not dst_file.exists():
                    shutil.copy2(src_file, dst_file)
                    copied += 1
                    self._logger(f"  + copied: {relative}")
                    _log.debug("Copied %s", relative)
                    self._emit_progress(progress_callback, progress, f"Copied {relative}")
                    continue

                if not self._files_equal(src_file, dst_file):
                    shutil.copy2(src_file, dst_file)
                    updated += 1
                    self._logger(f"  * updated: {relative}")
                    _log.debug("Updated %s", relative)
                    self._emit_progress(progress_callback, progress, f"Updated {relative}")
                else:
                    skipped += 1
                    self._emit_progress(progress_callback, progress, f"Checked {relative}")
            except OSError as exc:
                self._logger(f"  [ERROR] Failed to sync file {relative}: {exc}")
                _log.error("File sync error for %s: %s", relative, exc)
                self._emit_progress(progress_callback, progress, f"Error: {relative}")

        removed = 0
        if delete_stale:
            for dst_file in list(target.rglob("*")):
                if dst_file.is_dir():
                    continue

                try:
                    relative = dst_file.relative_to(target)
                except ValueError:
                    continue
                if self._is_git_metadata(relative):
                    continue

                src_file = source / relative
                if not src_file.exists():
                    try:
                        dst_file.unlink()
                        removed += 1
                        self._logger(f"  - removed stale file: {relative}")
                        _log.debug("Removed stale %s", relative)
                    except OSError as exc:
                        self._logger(f"  [ERROR] Cannot remove stale file {relative}: {exc}")
                        _log.error("Cannot remove stale file %s: %s", relative, exc)
                    self._emit_progress(progress_callback, progress, f"Removed stale {relative}")
                else:
                    self._emit_progress(progress_callback, progress, f"Validated {relative}")

        self._logger(
            f"[DONE] copied={copied}, updated={updated}, skipped={skipped}, removed={removed}"
        )
        _log.info("One-way done: copied=%d, updated=%d, skipped=%d, removed=%d", copied, updated, skipped, removed)

    @staticmethod
    def _file_sha256(file_path: Path) -> str:
        hasher = hashlib.sha256()
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _files_equal(self, source_file: Path, target_file: Path) -> bool:
        try:
            src_stat = source_file.stat()
            dst_stat = target_file.stat()

            if src_stat.st_size != dst_stat.st_size:
                return False

            return self._file_sha256(source_file) == self._file_sha256(target_file)
        except OSError as exc:
            _log.warning("File comparison error %s vs %s: %s", source_file, target_file, exc)
            return False

    @staticmethod
    def _emit_progress(progress_callback: Optional[ProgressCallback], progress: dict, message: str) -> None:
        progress["done"] += 1
        if progress_callback:
            progress_callback(progress["done"], progress["total"], message)
