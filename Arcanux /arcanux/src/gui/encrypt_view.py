"""
Protect view — the encrypt-then-embed workflow. Deliberately shows the
capacity check result BEFORE the user commits to running the (still
fast, but not instant) full protect operation, so a mismatch is caught
with one click instead of after a completed-but-wrong operation.
"""

import base64

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QMessageBox, QGroupBox, QRadioButton, QTextEdit, QButtonGroup
)

from ..core import orchestrator
from .app_state import AppState
from .workers import Worker
from .layout_utils import build_centered_view


class ProtectView(QWidget):
    def __init__(self, app_state: AppState, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.threadpool = QThreadPool.globalInstance()
        self.input_file_path = None
        self.carrier_path = None
        self.output_path = None
        self._build_ui()

    def _build_ui(self):
        layout = build_centered_view(self)

        # -- File to protect --
        file_group = QGroupBox("1. File to Protect")
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected.")
        self.file_label.setWordWrap(True)
        pick_file_btn = QPushButton("Choose File…")
        pick_file_btn.clicked.connect(self._pick_input_file)
        file_layout.addWidget(self.file_label, stretch=1)
        file_layout.addWidget(pick_file_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # -- Carrier image --
        carrier_group = QGroupBox("2. Carrier Image")
        carrier_layout = QVBoxLayout()

        picker_row = QHBoxLayout()
        self.carrier_label = QLabel("No carrier selected.")
        self.carrier_label.setWordWrap(True)
        pick_carrier_btn = QPushButton("Choose Image…")
        pick_carrier_btn.clicked.connect(self._pick_carrier)
        picker_row.addWidget(self.carrier_label, stretch=1)
        picker_row.addWidget(pick_carrier_btn)
        carrier_layout.addLayout(picker_row)

        format_note = QLabel(
            "You can pick any common image format (PNG, BMP, JPEG, TIFF, WEBP) as your "
            "carrier — Arcanux converts it internally. The output, however, is ALWAYS "
            "saved as PNG. This isn't a restriction for its own sake: hidden data lives "
            "in the exact least-significant bit of each pixel, and JPEG's lossy "
            "compression rewrites those bits during its own encoding — saving as JPEG "
            "would silently destroy the hidden payload. PNG is lossless, so what gets "
            "embedded is exactly what comes back out."
        )
        format_note.setWordWrap(True)
        format_note.setStyleSheet("color: palette(mid); font-size: 11px;")
        carrier_layout.addWidget(format_note)

        carrier_group.setLayout(carrier_layout)
        layout.addWidget(carrier_group)

        # -- Recipient --
        recipient_group = QGroupBox("3. Recipient Public Key")
        recipient_layout = QVBoxLayout()

        self.use_own_key_radio = QRadioButton("Use my own loaded identity (protect for myself)")
        self.use_pasted_key_radio = QRadioButton("Paste a recipient's public key (base64)")
        self.use_own_key_radio.setChecked(True)
        radio_group = QButtonGroup(self)
        radio_group.addButton(self.use_own_key_radio)
        radio_group.addButton(self.use_pasted_key_radio)
        recipient_layout.addWidget(self.use_own_key_radio)
        recipient_layout.addWidget(self.use_pasted_key_radio)

        self.pasted_key_text = QLineEdit()
        self.pasted_key_text.setPlaceholderText("Paste recipient's base64 public key here…")
        self.pasted_key_text.setEnabled(False)
        self.use_pasted_key_radio.toggled.connect(self.pasted_key_text.setEnabled)
        recipient_layout.addWidget(self.pasted_key_text)

        recipient_group.setLayout(recipient_layout)
        layout.addWidget(recipient_group)

        # -- Capacity check + status --
        self.capacity_label = QLabel("")
        self.capacity_label.setWordWrap(True)
        layout.addWidget(self.capacity_label)

        check_btn = QPushButton("Check Capacity")
        check_btn.clicked.connect(self._check_capacity)
        layout.addWidget(check_btn)

        # -- Protect button --
        self.protect_btn = QPushButton("Protect File →")
        self.protect_btn.setObjectName("primaryAction")
        self.protect_btn.setEnabled(False)
        self.protect_btn.clicked.connect(self._on_protect_clicked)
        layout.addWidget(self.protect_btn)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        layout.addStretch()

    # -- File pickers ---------------------------------------------------

    def _pick_input_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose File to Protect")
        if path:
            self.input_file_path = path
            self.file_label.setText(path)
            self._update_protect_enabled()

    def _pick_carrier(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose Carrier Image", "",
            "Images (*.png *.bmp *.jpg *.jpeg *.tiff *.webp)"
        )
        if path:
            self.carrier_path = path
            self.carrier_label.setText(path)
            self._update_protect_enabled()

    def _update_protect_enabled(self):
        self.protect_btn.setEnabled(bool(self.input_file_path and self.carrier_path))

    # -- Recipient resolution --------------------------------------------

    def _resolve_recipient_public_key(self) -> bytes | None:
        if self.use_own_key_radio.isChecked():
            if not self.app_state.is_unlocked():
                QMessageBox.warning(
                    self, "No Identity Loaded",
                    "Load or generate a keypair in the Keys tab first, or paste a recipient's key instead."
                )
                return None
            return self.app_state.current_keypair.public_key
        else:
            text = self.pasted_key_text.text().strip()
            if not text:
                QMessageBox.warning(self, "Missing Key", "Paste a recipient's public key first.")
                return None
            try:
                return base64.b64decode(text, validate=True)
            except Exception:
                QMessageBox.critical(self, "Invalid Key", "That doesn't look like valid base64.")
                return None

    # -- Capacity check ---------------------------------------------------

    def _check_capacity(self):
        if not (self.input_file_path and self.carrier_path):
            QMessageBox.warning(self, "Missing Selection", "Choose a file and a carrier image first.")
            return
        try:
            size = orchestrator.check_fits(self.input_file_path, self.carrier_path)
            self.capacity_label.setText(
                f"✓ Fits. Sealed payload will be {size:,} bytes."
            )
        except orchestrator.PayloadTooLargeError as e:
            self.capacity_label.setText(f"✗ {e}")
        except Exception as e:
            self.capacity_label.setText(f"Could not check capacity: {e}")

    # -- Protect ------------------------------------------------------------

    def _on_protect_clicked(self):
        recipient_key = self._resolve_recipient_public_key()
        if recipient_key is None:
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Protected Image As", "protected.png", "PNG Image (*.png)"
        )
        if not output_path:
            return

        self.protect_btn.setEnabled(False)
        self.status_label.setText("Protecting file…")

        worker = Worker(
            orchestrator.protect_file,
            self.input_file_path, self.carrier_path, recipient_key, output_path
        )
        worker.signals.finished.connect(lambda _: self._on_protect_done(output_path))
        worker.signals.error.connect(self._on_protect_error)
        self.threadpool.start(worker)

    def _on_protect_done(self, output_path: str):
        self.protect_btn.setEnabled(True)
        self.status_label.setText(f"Done. Saved to {output_path}")
        QMessageBox.information(self, "Success", f"File protected and saved to:\n{output_path}")

    def _on_protect_error(self, message: str):
        self.protect_btn.setEnabled(True)
        if "PayloadTooLargeError" in message:
            self.status_label.setText(f"Failed: payload too large for carrier. {message}")
        else:
            self.status_label.setText(f"Failed: {message}")
        QMessageBox.critical(self, "Protect Failed", message)
