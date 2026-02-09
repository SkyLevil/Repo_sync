from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography.fernet import Fernet
from PySide6.QtCore import QSettings, QTimer
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
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


@dataclass
class SyncPair:
    source: Path
    target: Path


class CredentialStore:
    def __init__(self, app_dir: Path):
        self._app_dir = app_dir
        self._app_dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self._app_dir / "secret.key"

    def _get_or_create_key(self) -> bytes:
        if self._key_path.exists():
            return self._key_path.read_bytes()

        key = Fernet.generate_key()
        self._key_path.write_bytes(key)
        return key

    def encrypt_payload(self, payload: Dict[str, str]) -> str:
        token = Fernet(self._get_or_create_key()).encrypt(json.dumps(payload).encode("utf-8"))
        return token.decode("utf-8")

    def decrypt_payload(self, token: str) -> Dict[str, str]:
        raw = Fernet(self._get_or_create_key()).decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))


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

        scheme_sep = "://"
        scheme, rest = repo_url.split(scheme_sep, maxsplit=1)
        return f"{scheme}{scheme_sep}{username}:{password}@{rest}"

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
        self.resize(1050, 700)

        self.settings = QSettings("RepoSync", "FolderSyncGui")
        self.app_data_dir = Path.home() / ".repo_sync_gui"
        self.credential_store = CredentialStore(self.app_data_dir)

        self.repo_root_edit = QLineEdit()
        self.repo_root_edit.setPlaceholderText(
            "Optional: Local repo root path or repository URL (https://..., git@..., ...)."
        )

        browse_repo_btn = QPushButton("Browse")
        browse_repo_btn.clicked.connect(self._pick_repo_root)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Optional repository username")

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Optional repository password/token")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.save_credentials_checkbox = QCheckBox("Save credentials encrypted")

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

        self.periodic_check_checkbox = QCheckBox("Enable periodic change checks")
        self.periodic_check_checkbox.stateChanged.connect(self._update_timer_state)

        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(5, 86400)
        self.interval_spinbox.setValue(60)
        self.interval_spinbox.setSuffix(" sec")
        self.interval_spinbox.valueChanged.connect(self._update_timer_state)

        self.auto_sync_on_change_checkbox = QCheckBox("Auto sync when changes are detected")

        sync_btn = QPushButton("Run sync now")
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
        top_grid.addWidget(QLabel("Username"), 1, 0)
        top_grid.addWidget(self.username_edit, 1, 1, 1, 2)
        top_grid.addWidget(QLabel("Password / Token"), 2, 0)
        top_grid.addWidget(self.password_edit, 2, 1, 1, 2)
        top_grid.addWidget(self.save_credentials_checkbox, 3, 1, 1, 2)
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

        watcher_row = QHBoxLayout()
        watcher_row.addWidget(self.periodic_check_checkbox)
        watcher_row.addWidget(QLabel("Check interval"))
        watcher_row.addWidget(self.interval_spinbox)
        watcher_row.addWidget(self.auto_sync_on_change_checkbox)
        watcher_row.addStretch()
        layout.addLayout(watcher_row)

        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)

        self.engine = SyncEngine(self._append_log)
        self.repo_resolver = RepoResolver(self._append_log)

        self.check_timer = QTimer(self)
        self.check_timer.timeout.connect(self._on_periodic_check)
        self.last_state_hash = ""

        self._load_settings()

        if self.table.rowCount() == 0:
            self._add_row()
            self._add_row()

        self._update_timer_state()

    def closeEvent(self, event):  # noqa: N802 (Qt API)
        self._save_settings()
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
        repo_base = self.repo_resolver.resolve(
            self.repo_root_edit.text(),
            username=self.username_edit.text().strip(),
            password=self.password_edit.text().strip(),
        )

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
            self.last_state_hash = self._calculate_state_hash(pairs)
            self._append_log("[SUCCESS] Sync finished.")
            self._save_settings()
        except Exception as exc:
            QMessageBox.critical(self, "Sync failed", str(exc))
            self._append_log(f"[ERROR] {exc}")

    def _update_timer_state(self) -> None:
        self.interval_spinbox.setEnabled(self.periodic_check_checkbox.isChecked())

        if not self.periodic_check_checkbox.isChecked():
            self.check_timer.stop()
            return

        self.check_timer.start(self.interval_spinbox.value() * 1000)
        self._append_log(
            f"[INFO] Periodic checks active (every {self.interval_spinbox.value()} seconds)."
        )

    def _on_periodic_check(self) -> None:
        try:
            self.repo_resolver.cleanup()
            pairs = self._collect_pairs()
            current_hash = self._calculate_state_hash(pairs)

            if not self.last_state_hash:
                self.last_state_hash = current_hash
                return

            if current_hash != self.last_state_hash:
                self._append_log("[INFO] Change detected in source folders.")
                self.last_state_hash = current_hash
                if self.auto_sync_on_change_checkbox.isChecked():
                    self._append_log("[INFO] Auto-sync triggered.")
                    self.engine.sync_pairs(
                        pairs=pairs,
                        two_way=self.two_way_checkbox.isChecked(),
                        delete_stale=self.delete_checkbox.isChecked(),
                    )
        except Exception as exc:
            self._append_log(f"[WARN] Periodic check failed: {exc}")

    @staticmethod
    def _calculate_state_hash(pairs: List[SyncPair]) -> str:
        hasher = hashlib.sha256()
        for pair in pairs:
            if not pair.source.exists() or not pair.source.is_dir():
                continue
            hasher.update(str(pair.source).encode("utf-8"))
            for file_path in sorted(p for p in pair.source.rglob("*") if p.is_file()):
                stat = file_path.stat()
                hasher.update(str(file_path).encode("utf-8"))
                hasher.update(str(stat.st_mtime_ns).encode("utf-8"))
                hasher.update(str(stat.st_size).encode("utf-8"))
        return hasher.hexdigest()

    def _save_settings(self) -> None:
        self.settings.setValue("repo_input", self.repo_root_edit.text())
        self.settings.setValue("two_way", self.two_way_checkbox.isChecked())
        self.settings.setValue("delete_stale", self.delete_checkbox.isChecked())
        self.settings.setValue("periodic_check", self.periodic_check_checkbox.isChecked())
        self.settings.setValue("interval_seconds", self.interval_spinbox.value())
        self.settings.setValue("auto_sync", self.auto_sync_on_change_checkbox.isChecked())
        self.settings.setValue("save_credentials", self.save_credentials_checkbox.isChecked())

        pairs: List[Dict[str, str]] = []
        for row in range(self.table.rowCount()):
            src_item = self.table.item(row, 0)
            dst_item = self.table.item(row, 1)
            pairs.append(
                {
                    "source": src_item.text().strip() if src_item else "",
                    "target": dst_item.text().strip() if dst_item else "",
                }
            )
        self.settings.setValue("pairs_json", json.dumps(pairs))

        if self.save_credentials_checkbox.isChecked():
            payload = {
                "username": self.username_edit.text().strip(),
                "password": self.password_edit.text().strip(),
            }
            encrypted = self.credential_store.encrypt_payload(payload)
            self.settings.setValue("credentials_encrypted", encrypted)
        else:
            self.settings.remove("credentials_encrypted")

        self.settings.sync()

    def _load_settings(self) -> None:
        self.repo_root_edit.setText(str(self.settings.value("repo_input", "")))
        self.two_way_checkbox.setChecked(self._to_bool(self.settings.value("two_way", False)))
        self.delete_checkbox.setChecked(self._to_bool(self.settings.value("delete_stale", False)))
        self.periodic_check_checkbox.setChecked(
            self._to_bool(self.settings.value("periodic_check", False))
        )
        self.interval_spinbox.setValue(int(self.settings.value("interval_seconds", 60)))
        self.auto_sync_on_change_checkbox.setChecked(
            self._to_bool(self.settings.value("auto_sync", False))
        )
        self.save_credentials_checkbox.setChecked(
            self._to_bool(self.settings.value("save_credentials", False))
        )

        pairs_json = str(self.settings.value("pairs_json", "[]"))
        try:
            pairs = json.loads(pairs_json)
        except json.JSONDecodeError:
            pairs = []

        self.table.setRowCount(0)
        for pair in pairs:
            self._add_row()
            row = self.table.rowCount() - 1
            self.table.setItem(row, 0, QTableWidgetItem(pair.get("source", "")))
            self.table.setItem(row, 1, QTableWidgetItem(pair.get("target", "")))

        encrypted_credentials = str(self.settings.value("credentials_encrypted", ""))
        if encrypted_credentials and self.save_credentials_checkbox.isChecked():
            try:
                payload = self.credential_store.decrypt_payload(encrypted_credentials)
                self.username_edit.setText(payload.get("username", ""))
                self.password_edit.setText(payload.get("password", ""))
            except Exception:
                self._append_log("[WARN] Could not decrypt stored credentials.")

    @staticmethod
    def _to_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes", "on"}


def main() -> None:
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()
