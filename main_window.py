from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, QRunnable, QSettings, QThreadPool, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from credential_store import CredentialStore
from git_publisher import GitPublisher
from repo_resolver import RepoResolver
from sync_engine import SyncEngine
from sync_models import SyncPair

REMOTE_WATCH_BRANCH = "main"


class WorkerSignals(QObject):
    finished = Signal(dict)
    error = Signal(str)
    log = Signal(str)
    progress = Signal(int, int, str)


class FunctionTask(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self._fn(*self._args, signals=self.signals, **self._kwargs)
            self.signals.finished.emit(result or {})
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Folder Sync (Repo URL / Local / Windows)")
        self.resize(1050, 760)

        self.settings = QSettings("RepoSync", "FolderSyncGui")
        self.app_data_dir = Path.home() / ".repo_sync_gui"
        self.credential_store = CredentialStore(self.app_data_dir)

        self.last_state_hash = ""
        self.check_in_progress = False
        self.sync_in_progress = False

        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(max(2, self.thread_pool.maxThreadCount()))

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

        self.periodic_check_checkbox = QCheckBox("Enable auto update checks")
        self.periodic_check_checkbox.stateChanged.connect(self._update_timer_state)

        self.continuous_watch_checkbox = QCheckBox("Continuous watch (ignore interval)")
        self.continuous_watch_checkbox.stateChanged.connect(self._update_timer_state)

        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(5, 86400)
        self.interval_spinbox.setValue(60)
        self.interval_spinbox.setSuffix(" sec")
        self.interval_spinbox.valueChanged.connect(self._update_timer_state)

        self.auto_sync_on_change_checkbox = QCheckBox("Auto sync on new commit/change")

        self.auto_push_checkbox = QCheckBox("Auto commit and push to GitHub after sync")
        self.push_branch_edit = QLineEdit("main")
        self.push_branch_edit.setPlaceholderText("Push branch (for example: main)")
        self.commit_message_edit = QLineEdit("Sync updates")
        self.commit_message_edit.setPlaceholderText("Commit message")

        sync_btn = QPushButton("Run sync now")
        sync_btn.clicked.connect(lambda: self._run_sync_async(show_error_dialog=True, clear_log=True))

        self.status_label = QLabel("Status: Idle")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("%p%")

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
        watcher_row.addWidget(self.continuous_watch_checkbox)
        watcher_row.addWidget(QLabel("Check interval"))
        watcher_row.addWidget(self.interval_spinbox)
        watcher_row.addWidget(self.auto_sync_on_change_checkbox)
        watcher_row.addStretch()
        layout.addLayout(watcher_row)

        push_row = QGridLayout()
        push_row.addWidget(self.auto_push_checkbox, 0, 0, 1, 2)
        push_row.addWidget(QLabel("Push branch"), 1, 0)
        push_row.addWidget(self.push_branch_edit, 1, 1)
        push_row.addWidget(QLabel("Commit message"), 2, 0)
        push_row.addWidget(self.commit_message_edit, 2, 1)
        layout.addLayout(push_row)

        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)

        self.check_timer = QTimer(self)
        self.check_timer.setSingleShot(True)
        self.check_timer.timeout.connect(self._on_periodic_check)

        self._load_settings()

        if self.table.rowCount() == 0:
            self._add_row()
            self._add_row()

        self._update_timer_state()

    def closeEvent(self, event):  # noqa: N802
        self._save_settings()
        self.check_timer.stop()
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

    def _snapshot_config(self) -> dict:
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

        return {
            "repo_input": self.repo_root_edit.text().strip(),
            "username": self.username_edit.text().strip(),
            "password": self.password_edit.text().strip(),
            "pairs": pairs,
            "two_way": self.two_way_checkbox.isChecked(),
            "delete_stale": self.delete_checkbox.isChecked(),
            "auto_push": self.auto_push_checkbox.isChecked(),
            "push_branch": self.push_branch_edit.text().strip() or "main",
            "commit_message": self.commit_message_edit.text().strip() or "Sync updates",
            "auto_sync": self.auto_sync_on_change_checkbox.isChecked(),
            "last_state_hash": self.last_state_hash,
        }

    @staticmethod
    def _build_pairs(config: dict, repo_base: Optional[Path]) -> List[SyncPair]:
        pairs: List[SyncPair] = []
        for idx, pair in enumerate(config["pairs"], start=1):
            source_text = pair.get("source", "").strip()
            target_text = pair.get("target", "").strip()

            if not source_text and not target_text:
                continue
            if not source_text or not target_text:
                raise ValueError(f"Row {idx}: both columns are required.")

            source_path = MainWindow._resolve_pair_path(source_text, repo_base, idx, "source")
            target_path = MainWindow._resolve_pair_path(target_text, repo_base, idx, "target")
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

    def _run_sync_async(self, show_error_dialog: bool, clear_log: bool) -> None:
        if self.sync_in_progress:
            self._append_log("[INFO] Sync already running.")
            return

        if clear_log:
            self.log.clear()
        self.progress_bar.setValue(0)
        self._set_status("Syncing in background...")
        self.sync_in_progress = True

        config = self._snapshot_config()
        task = FunctionTask(self._sync_job, config)
        task.signals.log.connect(self._append_log)
        task.signals.progress.connect(self._on_progress)
        task.signals.error.connect(lambda e: self._on_sync_error(e, show_error_dialog))
        task.signals.finished.connect(self._on_sync_finished)
        self.thread_pool.start(task)

    def _on_progress(self, done: int, total: int, message: str) -> None:
        percent = int((done / max(total, 1)) * 100)
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"{percent}% - {message}")

    def _sync_job(self, config: dict, signals: WorkerSignals) -> dict:
        logger = lambda msg: signals.log.emit(msg)
        resolver = RepoResolver(logger, cache_dir=self.app_data_dir / "repo_cache")
        repo_base = resolver.resolve(config["repo_input"], config["username"], config["password"])
        pairs = self._build_pairs(config, repo_base)

        engine = SyncEngine(logger)
        engine.sync_pairs(
            pairs=pairs,
            two_way=config["two_way"],
            delete_stale=config["delete_stale"],
            progress_callback=lambda d, t, m: signals.progress.emit(d, t, m),
        )

        if config["auto_push"]:
            if repo_base is None:
                logger("[WARN] Auto push skipped: repo path unresolved.")
            else:
                logger("[INFO] Auto commit/push started...")
                GitPublisher(logger).commit_and_push(repo_base, config["push_branch"], config["commit_message"])

        new_state = self._compute_state_value(config, pairs, resolver)
        return {"new_state": new_state}

    def _on_sync_error(self, error_text: str, show_error_dialog: bool) -> None:
        self.sync_in_progress = False
        self._set_status("Idle")
        self._append_log(f"[ERROR] {error_text}")
        if show_error_dialog:
            QMessageBox.critical(self, "Sync failed", error_text)

    def _on_sync_finished(self, result: dict) -> None:
        self.sync_in_progress = False
        self.last_state_hash = result.get("new_state", self.last_state_hash)
        self._append_log("[SUCCESS] Sync finished.")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - done")
        self._set_status("Idle")
        self._save_settings()

    def _schedule_next_check(self) -> None:
        if not self.periodic_check_checkbox.isChecked():
            return
        self.check_timer.start(1000 if self.continuous_watch_checkbox.isChecked() else self.interval_spinbox.value() * 1000)

    def _update_timer_state(self) -> None:
        self.interval_spinbox.setEnabled(
            self.periodic_check_checkbox.isChecked() and not self.continuous_watch_checkbox.isChecked()
        )
        self.check_timer.stop()
        if not self.periodic_check_checkbox.isChecked():
            self._set_status("Idle")
            return

        mode = "continuous" if self.continuous_watch_checkbox.isChecked() else "interval"
        self._append_log(f"[INFO] Auto update checks active ({mode}, branch '{REMOTE_WATCH_BRANCH}').")
        self._set_status("Watching for new commits/changes...")
        self._schedule_next_check()

    def _on_periodic_check(self) -> None:
        if self.check_in_progress:
            self._schedule_next_check()
            return

        self.check_in_progress = True
        self._set_status("Checking for new commits/changes (background)...")

        config = self._snapshot_config()
        task = FunctionTask(self._check_job, config)
        task.signals.log.connect(self._append_log)
        task.signals.error.connect(self._on_check_error)
        task.signals.finished.connect(self._on_check_finished)
        self.thread_pool.start(task)

    def _check_job(self, config: dict, signals: WorkerSignals) -> dict:
        logger = lambda msg: signals.log.emit(msg)
        resolver = RepoResolver(logger, cache_dir=self.app_data_dir / "repo_cache")

        if config["repo_input"] and RepoResolver.is_repo_url(config["repo_input"]):
            new_state = resolver.get_remote_branch_head(
                config["repo_input"],
                branch=REMOTE_WATCH_BRANCH,
                username=config["username"],
                password=config["password"],
            )
        else:
            repo_base = resolver.resolve(config["repo_input"], config["username"], config["password"])
            pairs = self._build_pairs(config, repo_base)
            new_state = self._calculate_state_hash(pairs)

        changed = config["last_state_hash"] != "" and new_state != config["last_state_hash"]
        return {"new_state": new_state, "changed": changed, "auto_sync": config["auto_sync"]}

    def _on_check_error(self, error_text: str) -> None:
        self.check_in_progress = False
        self._append_log(f"[WARN] Periodic check failed: {error_text}")
        self._set_status("Watching for new commits/changes...")
        self._schedule_next_check()

    def _on_check_finished(self, result: dict) -> None:
        self.check_in_progress = False
        new_state = result.get("new_state", "")

        if not self.last_state_hash and new_state:
            self.last_state_hash = new_state
            self._append_log(f"[INFO] Baseline captured for branch '{REMOTE_WATCH_BRANCH}'.")
        elif result.get("changed"):
            self._append_log("[INFO] New commit/change detected.")
            self.last_state_hash = new_state
            if result.get("auto_sync"):
                self._run_sync_async(show_error_dialog=False, clear_log=False)
        else:
            self._append_log("[INFO] No new commits/changes detected.")

        self._set_status("Watching for new commits/changes...")
        self._schedule_next_check()

    def _compute_state_value(self, config: dict, pairs: List[SyncPair], resolver: RepoResolver) -> str:
        if config["repo_input"] and RepoResolver.is_repo_url(config["repo_input"]):
            return resolver.get_remote_branch_head(
                config["repo_input"],
                branch=REMOTE_WATCH_BRANCH,
                username=config["username"],
                password=config["password"],
            )
        return self._calculate_state_hash(pairs)

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
        self.settings.setValue("continuous_watch", self.continuous_watch_checkbox.isChecked())
        self.settings.setValue("interval_seconds", self.interval_spinbox.value())
        self.settings.setValue("auto_sync", self.auto_sync_on_change_checkbox.isChecked())
        self.settings.setValue("auto_push", self.auto_push_checkbox.isChecked())
        self.settings.setValue("push_branch", self.push_branch_edit.text())
        self.settings.setValue("commit_message", self.commit_message_edit.text())
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
        self.continuous_watch_checkbox.setChecked(self._to_bool(self.settings.value("continuous_watch", False)))
        self.interval_spinbox.setValue(int(self.settings.value("interval_seconds", 60)))
        self.auto_sync_on_change_checkbox.setChecked(self._to_bool(self.settings.value("auto_sync", False)))
        self.auto_push_checkbox.setChecked(self._to_bool(self.settings.value("auto_push", False)))
        self.push_branch_edit.setText(str(self.settings.value("push_branch", "main")))
        self.commit_message_edit.setText(str(self.settings.value("commit_message", "Sync updates")))
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
