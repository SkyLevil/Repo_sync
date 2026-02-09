from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable, List

from sync_models import SyncPair


class SyncEngine:
    def __init__(self, logger: Callable[[str], None]):
        self._logger = logger

    def sync_pairs(self, pairs: List[SyncPair], two_way: bool, delete_stale: bool) -> None:
        for pair in pairs:
            source = pair.source
            target = pair.target

            if not source.exists() or not source.is_dir():
                self._logger(f"[SKIP] Source folder does not exist: {source}")
                continue

            if not target.exists():
                self._logger(f"[INFO] Creating target folder: {target}")
                target.mkdir(parents=True, exist_ok=True)

            self._logger(f"[SYNC] {source} -> {target}")
            self._sync_one_way(source, target, delete_stale)

            if two_way:
                self._logger(f"[SYNC] {target} -> {source}")
                self._sync_one_way(target, source, delete_stale)

    def _sync_one_way(self, source: Path, target: Path, delete_stale: bool) -> None:
        copied, updated, skipped = 0, 0, 0

        for src_file in source.rglob("*"):
            if src_file.is_dir():
                continue

            relative = src_file.relative_to(source)
            dst_file = target / relative
            dst_file.parent.mkdir(parents=True, exist_ok=True)

            if not dst_file.exists():
                shutil.copy2(src_file, dst_file)
                copied += 1
                self._logger(f"  + copied: {relative}")
                continue

            src_stat = src_file.stat()
            dst_stat = dst_file.stat()

            if src_stat.st_mtime > dst_stat.st_mtime or src_stat.st_size != dst_stat.st_size:
                shutil.copy2(src_file, dst_file)
                updated += 1
                self._logger(f"  * updated: {relative}")
            else:
                skipped += 1

        removed = 0
        if delete_stale:
            for dst_file in target.rglob("*"):
                if dst_file.is_dir():
                    continue

                relative = dst_file.relative_to(target)
                src_file = source / relative
                if not src_file.exists():
                    dst_file.unlink()
                    removed += 1
                    self._logger(f"  - removed stale file: {relative}")

        self._logger(
            f"[DONE] copied={copied}, updated={updated}, skipped={skipped}, removed={removed}"
        )
