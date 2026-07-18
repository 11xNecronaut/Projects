"""
Reveal view — the extract-then-decrypt workflow. Requires an unlocked
identity in AppState (loaded via the Keys tab) since decryption needs
the secret key, which this view never touches or stores directly.
"""

from pathlib import Path

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QMessageBox, QGroupBox
)

from ..core import orchestrator
from .app_state import AppState
from .workers import Worker
from .layout_utils import build_centered_view


class RevealView(QWidget):
    def __init__(self, app_state: AppState, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.threadpool = QThreadPool.globalInstance()
        self.stego_path = None
        self._build_ui()

    def _build_ui(self):
        layout = build_centered_view(self)

        intro = QLabel(
            "Reveal extracts and decrypts a file previously protected with "
            "Arcanux. You need the identity (keypair) the file was "
            "protected for — load it in the Keys tab first."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        file_group = QGroupBox("Protected Image")
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No image selected.")
        self.file_label.setWordWrap(True)
        pick_btn = QPushButton("Choose Image…")
        pick_btn.clicked.connect(self._pick_stego_image)
        file_layout.addWidget(self.file_label, stretch=1)
        file_layout.addWidget(pick_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        self.reveal_btn = QPushButton("Reveal File →")
        self.reveal_btn.setObjectName("primaryAction")
        self.reveal_btn.setEnabled(False)
        self.reveal_btn.clicked.connect(self._on_reveal_clicked)
        layout.addWidget(self.reveal_btn)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        layout.addStretch()

    def _pick_stego_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose Protected Image", "", "PNG Image (*.png)"
        )
        if path:
            self.stego_path = path
            self.file_label.setText(path)
            self.reveal_btn.setEnabled(True)

    def _on_reveal_clicked(self):
        if not self.app_state.is_unlocked():
            QMessageBox.warning(
                self, "No Identity Loaded",
                "Load your keystore in the Keys tab first — decryption needs your secret key."
            )
            return
        if not self.stego_path:
            return

        self.reveal_btn.setEnabled(False)
        self.status_label.setText("Extracting and decrypting…")

        secret_key = self.app_state.current_keypair.secret_key
        worker = Worker(orchestrator.reveal_file, self.stego_path, secret_key)
        worker.signals.finished.connect(self._on_reveal_done)
        worker.signals.error.connect(self._on_reveal_error)
        self.threadpool.start(worker)

    def _on_reveal_done(self, revealed):
        self.reveal_btn.setEnabled(True)
        default_name = revealed.filename or "revealed_file"
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Revealed File As", default_name)
        if not save_path:
            self.status_label.setText("Revealed successfully, but not saved (cancelled).")
            return
        Path(save_path).write_bytes(revealed.data)
        self.status_label.setText(f"Saved to {save_path}")
        QMessageBox.information(self, "Success", f"File revealed and saved to:\n{save_path}")

    def _on_reveal_error(self, message: str):
        self.reveal_btn.setEnabled(True)
        if "DecryptionError" in message:
            friendly = ("Decryption failed. This usually means the wrong identity is "
                        "loaded for this file, or the image was modified/corrupted after protection.")
            self.status_label.setText(friendly)
            QMessageBox.critical(self, "Reveal Failed", friendly)
        elif "ExtractionError" in message or "ContainerFormatError" in message:
            friendly = ("No valid Arcanux data found in this image. It may not have "
                        "been protected with Arcanux, or it was re-saved in a lossy format.")
            self.status_label.setText(friendly)
            QMessageBox.critical(self, "Reveal Failed", friendly)
        else:
            self.status_label.setText(f"Failed: {message}")
            QMessageBox.critical(self, "Reveal Failed", message)
