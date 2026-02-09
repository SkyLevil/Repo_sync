from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import (
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

from credential_store import CredentialStore
from repo_resolver import RepoResolver
from sync_engine import SyncEngine
from sync_models import SyncPair


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Folder Sync (Repo URL / Local / Windows)")
        self.resize(1050, 700)

        self.settings = QSettings("RepoSync", "FolderSyncGui")
        self.app_data_dir = Path.home() / ".repo_sync_gui"
        self.credential_store = CredentialStore(self.app_data_dir)

        self.last_state_hash = ""
        self.check_in_progress = False

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
        sync_btn.clicked.connect(lambda: self._run_sync(show_error_dialog=True, clear_log=True))

        self.status_label = QLabel("Status: Idle")
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

        layout.addWidget(self.status_label)
        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)

        self.engine = SyncEngine(self._append_log)
        self.repo_resolver = RepoResolver(self._append_log)

        self.check_timer = QTimer(self)
        self.check_timer.timeout.connect(self._on_periodic_check)

        self._load_settings()

        if self.table.rowCount() == 0:
            self._add_row()
            self._add_row()

        self._update_timer_state()

    def closeEvent(self, event):  # noqa: N802
        self._save_settings()
        self.repo_resolver.cleanup()
        super().closeEvent(event)

    def _set_status(self, text: str) -> None:
        self.status_label.setText(f"Status: {text}")

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

    def _run_sync(self, show_error_dialog: bool, clear_log: bool) -> bool:
        if clear_log:
            self.log.clear()

        self._set_status("Syncing...")
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
            self._set_status("Idle")
            return True
        except Exception as exc:
            if show_error_dialog:
                QMessageBox.critical(self, "Sync failed", str(exc))
            self._append_log(f"[ERROR] {exc}")
            self._set_status("Idle")
            return False

    def _update_timer_state(self) -> None:
        self.interval_spinbox.setEnabled(self.periodic_check_checkbox.isChecked())

        if not self.periodic_check_checkbox.isChecked():
            self.check_timer.stop()
            self._set_status("Idle")
            return

        self.check_timer.start(self.interval_spinbox.value() * 1000)
        self._append_log(
            f"[INFO] Periodic checks active (every {self.interval_spinbox.value()} seconds)."
        )
        self._set_status("Watching for changes...")

    def _on_periodic_check(self) -> None:
        if self.check_in_progress:
            self._append_log("[INFO] Previous check still running, skipping this cycle.")
            return

        self.check_in_progress = True
        self._set_status("Checking for changes...")

        try:
            changed, new_state = self._detect_changes()

            if not self.last_state_hash:
                self.last_state_hash = new_state
                self._append_log("[INFO] Baseline captured for auto-sync checks.")
                self._set_status("Watching for changes...")
                return

            if changed:
                self._append_log("[INFO] Change detected in source repository/folders.")
                self.last_state_hash = new_state
                if self.auto_sync_on_change_checkbox.isChecked():
                    self._append_log("[INFO] Auto-sync is running now...")
                    self._set_status("Auto-sync in progress...")
                    ok = self._run_sync(show_error_dialog=False, clear_log=False)
                    if ok:
                        self._append_log("[INFO] Auto-sync completed.")
                    else:
                        self._append_log("[WARN] Auto-sync failed.")
                else:
                    self._append_log("[INFO] Auto-sync is disabled; no sync executed.")
            else:
                self._append_log("[INFO] No changes detected.")

            self._set_status("Watching for changes...")
        except Exception as exc:
            self._append_log(f"[WARN] Periodic check failed: {exc}")
            self._set_status("Watching for changes...")
        finally:
            self.check_in_progress = False

    def _detect_changes(self) -> tuple[bool, str]:
        repo_input = self.repo_root_edit.text().strip()
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()

        if repo_input and RepoResolver.is_repo_url(repo_input):
            remote_head = self.repo_resolver.get_remote_head(repo_input, username=username, password=password)
            return (self.last_state_hash != "" and remote_head != self.last_state_hash), remote_head

        self.repo_resolver.cleanup()
        pairs = self._collect_pairs()
        current_hash = self._calculate_state_hash(pairs)
        return (self.last_state_hash != "" and current_hash != self.last_state_hash), current_hash

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
            self.settings.setValue("credentials_encrypted", self.credential_store.encrypt_payload(payload))
        else:
            self.settings.remove("credentials_encrypted")

        self.settings.sync()

    def _load_settings(self) -> None:
        self.repo_root_edit.setText(str(self.settings.value("repo_input", "")))
        self.two_way_checkbox.setChecked(self._to_bool(self.settings.value("two_way", False)))
        self.delete_checkbox.setChecked(self._to_bool(self.settings.value("delete_stale", False)))
        self.periodic_check_checkbox.setChecked(self._to_bool(self.settings.value("periodic_check", False)))
        self.interval_spinbox.setValue(int(self.settings.value("interval_seconds", 60)))
        self.auto_sync_on_change_checkbox.setChecked(self._to_bool(self.settings.value("auto_sync", False)))
        self.save_credentials_checkbox.setChecked(self._to_bool(self.settings.value("save_credentials", False)))

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
