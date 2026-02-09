from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QObject, QRunnable, QSettings, QThreadPool, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
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
TYPE_PATH = "Path"
TYPE_REPO = "Repository URL"


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
        self.setWindowTitle("Folder Sync (Path <-> Repository URL)")
        self.resize(1100, 780)

        self.settings = QSettings("RepoSync", "FolderSyncGui")
        self.app_data_dir = Path.home() / ".repo_sync_gui"
        self.credential_store = CredentialStore(self.app_data_dir)

        self.last_state_hash = ""
        self.check_in_progress = False
        self.sync_in_progress = False

        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(max(2, self.thread_pool.maxThreadCount()))

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Optional repository username")

        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Optional repository password/token")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self.save_credentials_checkbox = QCheckBox("Save credentials encrypted")

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Source type", "Source", "Target type", "Target"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)

        add_row_btn = QPushButton("Add sync pair")
        add_row_btn.clicked.connect(self._add_row)
        remove_row_btn = QPushButton("Remove selected pair")
        remove_row_btn.clicked.connect(self._remove_selected_rows)

        browse_source_btn = QPushButton("Browse source path")
        browse_source_btn.clicked.connect(lambda: self._pick_path_for_selected(column=1, type_column=0))
        browse_target_btn = QPushButton("Browse target path")
        browse_target_btn.clicked.connect(lambda: self._pick_path_for_selected(column=3, type_column=2))

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

        self.auto_push_checkbox = QCheckBox("Auto commit and push repository targets after sync")
        self.auto_push_checkbox.setChecked(True)
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
        top_grid.addWidget(QLabel("Username"), 0, 0)
        top_grid.addWidget(self.username_edit, 0, 1)
        top_grid.addWidget(QLabel("Password / Token"), 1, 0)
        top_grid.addWidget(self.password_edit, 1, 1)
        top_grid.addWidget(self.save_credentials_checkbox, 2, 1)
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

    def _create_type_combo(self, value: str = TYPE_PATH) -> QComboBox:
        combo = QComboBox()
        combo.addItems([TYPE_PATH, TYPE_REPO])
        combo.setCurrentText(value if value in (TYPE_PATH, TYPE_REPO) else TYPE_PATH)
        return combo

    def _add_row(self) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setCellWidget(row, 0, self._create_type_combo(TYPE_PATH))
        self.table.setItem(row, 1, QTableWidgetItem(""))
        self.table.setCellWidget(row, 2, self._create_type_combo(TYPE_PATH))
        self.table.setItem(row, 3, QTableWidgetItem(""))

    def _remove_selected_rows(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        for row in rows:
            self.table.removeRow(row)

    def _pick_path_for_selected(self, column: int, type_column: int) -> None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Selection required", "Please select a row first.")
            return

        combo = self.table.cellWidget(row, type_column)
        selected_type = combo.currentText() if isinstance(combo, QComboBox) else TYPE_PATH
        if selected_type != TYPE_PATH:
            QMessageBox.information(self, "Path only", "Path picker only works when type is 'Path'.")
            return

        selected = QFileDialog.getExistingDirectory(self, "Select folder path")
        if selected:
            self.table.setItem(row, column, QTableWidgetItem(selected))

    def _snapshot_config(self) -> dict:
        pairs: List[Dict[str, str]] = []
        for row in range(self.table.rowCount()):
            source_type_combo = self.table.cellWidget(row, 0)
            target_type_combo = self.table.cellWidget(row, 2)
            source_type = source_type_combo.currentText() if isinstance(source_type_combo, QComboBox) else TYPE_PATH
            target_type = target_type_combo.currentText() if isinstance(target_type_combo, QComboBox) else TYPE_PATH

            src_item = self.table.item(row, 1)
            dst_item = self.table.item(row, 3)
            pairs.append(
                {
                    "source_type": source_type,
                    "source": src_item.text().strip() if src_item else "",
                    "target_type": target_type,
                    "target": dst_item.text().strip() if dst_item else "",
                }
            )

        return {
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
    def _resolve_endpoint(
        resolver: RepoResolver,
        endpoint_type: str,
        endpoint_value: str,
        username: str,
        password: str,
    ) -> Tuple[Path, Optional[str]]:
        if endpoint_type == TYPE_REPO:
            path = resolver.resolve(endpoint_value, username=username, password=password)
            if path is None:
                raise ValueError("Repository URL is empty.")
            return path, endpoint_value

        if not endpoint_value:
            raise ValueError("Path value is empty.")
        path = Path(endpoint_value)
        if not path.is_absolute():
            raise ValueError(f"Path must be absolute: {endpoint_value}")
        return path, None

    @staticmethod
    def _build_pairs(config: dict, resolver: RepoResolver) -> Tuple[List[SyncPair], List[Tuple[Path, str]]]:
        pairs: List[SyncPair] = []
        repo_targets: List[Tuple[Path, str]] = []

        for idx, pair in enumerate(config["pairs"], start=1):
            src_type = pair.get("source_type", TYPE_PATH)
            src_value = pair.get("source", "").strip()
            dst_type = pair.get("target_type", TYPE_PATH)
            dst_value = pair.get("target", "").strip()

            if not src_value and not dst_value:
                continue
            if not src_value or not dst_value:
                raise ValueError(f"Row {idx}: both source and target are required.")

            source_path, _ = MainWindow._resolve_endpoint(
                resolver, src_type, src_value, config["username"], config["password"]
            )
            target_path, target_repo_url = MainWindow._resolve_endpoint(
                resolver, dst_type, dst_value, config["username"], config["password"]
            )

            pairs.append(SyncPair(source=source_path, target=target_path))
            if target_repo_url:
                repo_targets.append((target_path, target_repo_url))

        if not pairs:
            raise ValueError("Please define at least one sync pair.")

        return pairs, repo_targets

    def _run_sync_async(self, show_error_dialog: bool, clear_log: bool) -> None:
        if self.sync_in_progress:
            self._append_log("[INFO] Sync already running.")
            return

        if clear_log:
            self.log.clear()

        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0%")
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

        pairs, repo_targets = self._build_pairs(config, resolver)
        unique_repo_targets = {}
        for repo_path, url in repo_targets:
            unique_repo_targets[str(repo_path)] = (repo_path, url)
            logger(f"[INFO] Active repository target: {url}")

        for repo_path, _url in unique_repo_targets.values():
            GitPublisher(logger).prepare_repository(repo_path, config["push_branch"])

        engine = SyncEngine(logger)
        engine.sync_pairs(
            pairs=pairs,
            two_way=config["two_way"],
            delete_stale=config["delete_stale"],
            progress_callback=lambda d, t, m: signals.progress.emit(d, t, m),
        )

        if config["auto_push"]:
            pushed_paths = set()
            for repo_path, repo_url in repo_targets:
                key = str(repo_path)
                if key in pushed_paths:
                    continue
                pushed_paths.add(key)
                logger(f"[INFO] Auto commit/push started on {repo_path} ({repo_url})...")
                GitPublisher(logger).commit_and_push(repo_path, config["push_branch"], config["commit_message"])

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

        new_state = self._compute_state_by_sources(config, resolver)
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

    def _compute_state_by_sources(self, config: dict, resolver: RepoResolver) -> str:
        hasher = hashlib.sha256()
        for pair in config["pairs"]:
            source_type = pair.get("source_type", TYPE_PATH)
            source_value = pair.get("source", "").strip()
            if not source_value:
                continue

            if source_type == TYPE_REPO:
                head = resolver.get_remote_branch_head(
                    source_value,
                    branch=REMOTE_WATCH_BRANCH,
                    username=config["username"],
                    password=config["password"],
                )
                hasher.update(source_value.encode("utf-8"))
                hasher.update(head.encode("utf-8"))
            else:
                path = Path(source_value)
                if not path.exists() or not path.is_dir():
                    continue
                hasher.update(str(path).encode("utf-8"))
                for file_path in sorted(p for p in path.rglob("*") if p.is_file()):
                    stat = file_path.stat()
                    hasher.update(str(file_path).encode("utf-8"))
                    hasher.update(str(stat.st_mtime_ns).encode("utf-8"))
                    hasher.update(str(stat.st_size).encode("utf-8"))

        return hasher.hexdigest()

    def _compute_state_value(self, config: dict, pairs: List[SyncPair], resolver: RepoResolver) -> str:
        # Keep compatibility by computing based on current source definitions from config.
        _ = pairs
        return self._compute_state_by_sources(config, resolver)

    def _save_settings(self) -> None:
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
            src_type_combo = self.table.cellWidget(row, 0)
            dst_type_combo = self.table.cellWidget(row, 2)
            src_item = self.table.item(row, 1)
            dst_item = self.table.item(row, 3)
            pairs.append(
                {
                    "source_type": src_type_combo.currentText() if isinstance(src_type_combo, QComboBox) else TYPE_PATH,
                    "source": src_item.text().strip() if src_item else "",
                    "target_type": dst_type_combo.currentText() if isinstance(dst_type_combo, QComboBox) else TYPE_PATH,
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
        self.two_way_checkbox.setChecked(self._to_bool(self.settings.value("two_way", False)))
        self.delete_checkbox.setChecked(self._to_bool(self.settings.value("delete_stale", False)))
        self.periodic_check_checkbox.setChecked(self._to_bool(self.settings.value("periodic_check", False)))
        self.continuous_watch_checkbox.setChecked(self._to_bool(self.settings.value("continuous_watch", False)))
        self.interval_spinbox.setValue(int(self.settings.value("interval_seconds", 60)))
        self.auto_sync_on_change_checkbox.setChecked(self._to_bool(self.settings.value("auto_sync", False)))
        self.auto_push_checkbox.setChecked(self._to_bool(self.settings.value("auto_push", True)))
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
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setCellWidget(row, 0, self._create_type_combo(pair.get("source_type", TYPE_PATH)))
            self.table.setItem(row, 1, QTableWidgetItem(pair.get("source", "")))
            self.table.setCellWidget(row, 2, self._create_type_combo(pair.get("target_type", TYPE_PATH)))
            self.table.setItem(row, 3, QTableWidgetItem(pair.get("target", "")))

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
