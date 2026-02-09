from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


@dataclass
class SyncPair:
    source: Path
    target: Path


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

    def resolve(self, repo_input: str) -> Optional[Path]:
        repo_input = repo_input.strip()
        if not repo_input:
            return None

        if self._looks_like_url(repo_input):
            return self._clone_repo(repo_input)

        repo_path = Path(repo_input)
        if not repo_path.exists() or not repo_path.is_dir():
            raise ValueError("Repo root path does not exist or is not a folder.")

        return repo_path

    def _clone_repo(self, repo_url: str) -> Path:
        self.cleanup()
        self._temp_dir = tempfile.TemporaryDirectory(prefix="repo_sync_")
        clone_target = Path(self._temp_dir.name) / "repo"

        self._logger(f"[INFO] Cloning repository: {repo_url}")
        process = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_target)],
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode != 0:
            self.cleanup()
            raise ValueError(f"Failed to clone repository URL.\n{process.stderr.strip()}")

        self._logger(f"[INFO] Repository cloned to temporary path: {clone_target}")
        return clone_target

    def cleanup(self) -> None:
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None


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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Folder Sync (Repo URL / Local / Windows)")
        self.resize(980, 650)

        self.repo_root_edit = QLineEdit()
        self.repo_root_edit.setPlaceholderText(
            "Optional: Local repo root path or repository URL (https://..., git@..., ...)."
        )

        browse_repo_btn = QPushButton("Browse")
        browse_repo_btn.clicked.connect(self._pick_repo_root)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Source folder", "Target folder"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        add_row_btn = QPushButton("Add sync pair")
        add_row_btn.clicked.connect(self._add_row)

        remove_row_btn = QPushButton("Remove selected pair")
        remove_row_btn.clicked.connect(self._remove_selected_rows)

        browse_source_btn = QPushButton("Choose source for selected row")
        browse_source_btn.clicked.connect(self._pick_source_for_selected)

        browse_target_btn = QPushButton("Choose target for selected row")
        browse_target_btn.clicked.connect(self._pick_target_for_selected)

        self.two_way_checkbox = QCheckBox("Two-way sync")
        self.delete_checkbox = QCheckBox("Delete stale files on destination")

        sync_btn = QPushButton("Run sync")
        sync_btn.clicked.connect(self._run_sync)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)

        root = QWidget()
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)

        top_grid = QGridLayout()
        top_grid.addWidget(QLabel("Repo root / Repo URL (optional)"), 0, 0)
        top_grid.addWidget(self.repo_root_edit, 0, 1)
        top_grid.addWidget(browse_repo_btn, 0, 2)
        layout.addLayout(top_grid)

        layout.addWidget(self.table)

        row_actions = QHBoxLayout()
        row_actions.addWidget(add_row_btn)
        row_actions.addWidget(remove_row_btn)
        row_actions.addWidget(browse_source_btn)
        row_actions.addWidget(browse_target_btn)
        row_actions.addStretch()
        layout.addLayout(row_actions)

        options = QHBoxLayout()
        options.addWidget(self.two_way_checkbox)
        options.addWidget(self.delete_checkbox)
        options.addStretch()
        options.addWidget(sync_btn)
        layout.addLayout(options)

        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)

        self._add_row()
        self._add_row()

        self.engine = SyncEngine(self._append_log)
        self.repo_resolver = RepoResolver(self._append_log)

    def closeEvent(self, event):  # noqa: N802 (Qt API)
        self.repo_resolver.cleanup()
        super().closeEvent(event)

    def _append_log(self, message: str) -> None:
        self.log.appendPlainText(message)

    def _pick_repo_root(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select repository root")
        if selected:
            self.repo_root_edit.setText(selected)

    def _add_row(self) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(""))
        self.table.setItem(row, 1, QTableWidgetItem(""))

    def _remove_selected_rows(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        for row in rows:
            self.table.removeRow(row)

    def _pick_source_for_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Selection required", "Please select a row first.")
            return

        selected = QFileDialog.getExistingDirectory(self, "Select source folder")
        if selected:
            self.table.setItem(row, 0, QTableWidgetItem(selected))

    def _pick_target_for_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Selection required", "Please select a row first.")
            return

        selected = QFileDialog.getExistingDirectory(self, "Select target folder")
        if selected:
            self.table.setItem(row, 1, QTableWidgetItem(selected))

    def _collect_pairs(self) -> List[SyncPair]:
        repo_base = self.repo_resolver.resolve(self.repo_root_edit.text())

        pairs: List[SyncPair] = []
        for row in range(self.table.rowCount()):
            src_item = self.table.item(row, 0)
            dst_item = self.table.item(row, 1)

            source_text = src_item.text().strip() if src_item else ""
            target_text = dst_item.text().strip() if dst_item else ""

            if not source_text and not target_text:
                continue
            if not source_text or not target_text:
                raise ValueError(f"Row {row + 1}: both columns are required.")

            source_path = self._resolve_pair_path(source_text, repo_base, row + 1, "source")
            target_path = self._resolve_pair_path(target_text, repo_base, row + 1, "target")

            pairs.append(SyncPair(source=source_path, target=target_path))

        if not pairs:
            raise ValueError("Please define at least one sync pair.")

        return pairs

    @staticmethod
    def _resolve_pair_path(raw_path: str, repo_base: Optional[Path], row_number: int, role: str) -> Path:
        candidate = Path(raw_path)

        if candidate.is_absolute():
            return candidate

        if repo_base is None:
            raise ValueError(
                f"Row {row_number}: relative {role} path '{raw_path}' needs a repo root path or repo URL."
            )

        return repo_base / candidate

    def _run_sync(self) -> None:
        self.log.clear()
        self.repo_resolver.cleanup()

        try:
            pairs = self._collect_pairs()
            self.engine.sync_pairs(
                pairs=pairs,
                two_way=self.two_way_checkbox.isChecked(),
                delete_stale=self.delete_checkbox.isChecked(),
            )
            self._append_log("[SUCCESS] Sync finished.")
        except Exception as exc:
            QMessageBox.critical(self, "Sync failed", str(exc))
            self._append_log(f"[ERROR] {exc}")


def main() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
