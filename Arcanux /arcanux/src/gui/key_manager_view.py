"""
Key Manager view — generate a new ML-KEM-768 keypair, save it password-
protected to disk, or load an existing keystore file. Every other view
depends on AppState.current_keypair being set from here.
"""

import base64

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QFileDialog, QInputDialog, QLineEdit, QMessageBox, QGroupBox
)

from ..crypto import kem
from ..core import keystore
from .app_state import AppState, fingerprint
from .workers import Worker
from . import themes
from .layout_utils import build_centered_view


class KeyManagerView(QWidget):
    def __init__(self, app_state: AppState, parent=None):
        super().__init__(parent)
        self.app_state = app_state
        self.threadpool = QThreadPool.globalInstance()
        self._build_ui()
        self._refresh_status()

    def _build_ui(self):
        layout = build_centered_view(self)

        intro = QLabel(
            "Your identity is one ML-KEM-768 keypair. The public key is safe to "
            "share with anyone who wants to send you a protected file. The "
            "secret key is encrypted on disk with a password you choose — "
            "guard that password, Arcanux cannot recover it for you."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        actions_group = QGroupBox("Manage Identity")
        actions_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate New Keypair")
        self.load_btn = QPushButton("Load Existing Keystore…")
        self.delete_btn = QPushButton("Delete Keystore…")
        self.generate_btn.setObjectName("primaryAction")
        self.delete_btn.setStyleSheet(themes.DESTRUCTIVE_BUTTON_QSS)
        self.generate_btn.clicked.connect(self._on_generate)
        self.load_btn.clicked.connect(self._on_load)
        self.delete_btn.clicked.connect(self._on_delete)
        actions_layout.addWidget(self.generate_btn)
        actions_layout.addWidget(self.load_btn)
        actions_layout.addWidget(self.delete_btn)
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        status_group = QGroupBox("Current Identity")
        status_layout = QVBoxLayout()
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)

        self.pubkey_text = QTextEdit()
        self.pubkey_text.setReadOnly(True)
        self.pubkey_text.setMaximumHeight(90)
        self.pubkey_text.setPlaceholderText("Public key (base64) will appear here once a key is loaded.")
        status_layout.addWidget(self.pubkey_text)

        copy_btn = QPushButton("Copy Public Key to Clipboard")
        copy_btn.clicked.connect(self._copy_public_key)
        status_layout.addWidget(copy_btn)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        layout.addStretch()

    def _refresh_status(self):
        if self.app_state.is_unlocked():
            fp = self.app_state.public_key_fingerprint()
            self.status_label.setText(f"Identity loaded. Fingerprint: {fp}")
            pk_b64 = base64.b64encode(self.app_state.current_keypair.public_key).decode()
            self.pubkey_text.setPlainText(pk_b64)
        else:
            self.status_label.setText("No identity loaded. Generate a new keypair or load an existing keystore.")
            self.pubkey_text.clear()

    def _copy_public_key(self):
        if not self.app_state.is_unlocked():
            QMessageBox.warning(self, "No Key Loaded", "Generate or load a keypair first.")
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.pubkey_text.toPlainText())
        QMessageBox.information(self, "Copied", "Public key copied to clipboard.")

    # -- Generate -----------------------------------------------------

    def _on_generate(self):
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save New Keystore As", "identity.arcx", "Arcanux Keystore (*.arcx)"
        )
        if not save_path:
            return

        password, ok = QInputDialog.getText(
            self, "Set Password", "Choose a password to protect this keystore:",
            QLineEdit.Password
        )
        if not ok or not password:
            return

        confirm, ok = QInputDialog.getText(
            self, "Confirm Password", "Re-enter the password:", QLineEdit.Password
        )
        if not ok or confirm != password:
            QMessageBox.critical(self, "Password Mismatch", "Passwords did not match. Try again.")
            return

        self.generate_btn.setEnabled(False)
        worker = Worker(self._generate_and_save, password, save_path)
        worker.signals.finished.connect(lambda kp: self._on_generate_done(kp, save_path))
        worker.signals.error.connect(self._on_worker_error)
        self.threadpool.start(worker)

    @staticmethod
    def _generate_and_save(password: str, save_path: str) -> kem.KeyPair:
        new_keypair = kem.generate_keypair()
        keystore.save_keypair(new_keypair, password, save_path)
        return new_keypair

    def _on_generate_done(self, new_keypair: kem.KeyPair, save_path: str):
        self.generate_btn.setEnabled(True)
        self.app_state.current_keypair = new_keypair
        self.app_state.current_keystore_path = save_path
        self._refresh_status()
        QMessageBox.information(
            self, "Keypair Generated",
            f"New identity created.\nFingerprint: {fingerprint(new_keypair.public_key)}\n\n"
            "Keep the keystore file and password safe — losing either means "
            "losing access to anything encrypted to this key."
        )

    # -- Load -----------------------------------------------------------

    def _on_load(self):
        open_path, _ = QFileDialog.getOpenFileName(
            self, "Load Keystore", "", "Arcanux Keystore (*.arcx)"
        )
        if not open_path:
            return

        password, ok = QInputDialog.getText(
            self, "Password", "Enter the keystore password:", QLineEdit.Password
        )
        if not ok:
            return

        self.load_btn.setEnabled(False)
        worker = Worker(keystore.load_keypair, password, open_path)
        worker.signals.finished.connect(lambda kp: self._on_load_done(kp, open_path))
        worker.signals.error.connect(self._on_load_error)
        self.threadpool.start(worker)

    def _on_load_done(self, loaded_keypair: kem.KeyPair, open_path: str):
        self.load_btn.setEnabled(True)
        self.app_state.current_keypair = loaded_keypair
        self.app_state.current_keystore_path = open_path
        self._refresh_status()
        QMessageBox.information(self, "Keystore Loaded", "Identity loaded successfully.")

    def _on_load_error(self, message: str):
        self.load_btn.setEnabled(True)
        if "WrongPasswordError" in message:
            QMessageBox.critical(self, "Wrong Password", "Incorrect password for this keystore.")
        else:
            QMessageBox.critical(self, "Load Failed", message)

    def _on_worker_error(self, message: str):
        self.generate_btn.setEnabled(True)
        self.load_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", message)

    # -- Delete -----------------------------------------------------------

    def _on_delete(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Keystore to Delete", "", "Arcanux Keystore (*.arcx)"
        )
        if not path:
            return

        confirm = QMessageBox.warning(
            self, "Delete Keystore — This Is Permanent",
            f"You are about to permanently delete:\n\n{path}\n\n"
            "This cannot be undone. Anyone who protected a file for the "
            "public key in this keystore will need a NEW key from you — "
            "the old one becomes useless the moment this file is gone. "
            "Files already protected with this key and not yet revealed "
            "will become permanently unrecoverable.\n\n"
            "Are you certain?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            self._secure_delete(path)
        except Exception as e:
            QMessageBox.critical(self, "Delete Failed", str(e))
            return

        if self.app_state.current_keystore_path == path:
            self.app_state.current_keypair = None
            self.app_state.current_keystore_path = None
            self._refresh_status()

        QMessageBox.information(self, "Deleted", "Keystore deleted.")

    @staticmethod
    def _secure_delete(path: str):
        """
        Best-effort overwrite-then-delete. Stated honestly: on modern
        SSDs and copy-on-write filesystems, overwriting a file's logical
        bytes does NOT guarantee the underlying physical storage is
        overwritten — wear-leveling and journaling can leave the old
        data recoverable via specialized tools regardless of what an
        application does at the file-I/O level. This is meaningfully
        better than a plain delete (which leaves data untouched and
        trivially recoverable with basic undelete tools) but is not a
        cryptographic guarantee. Documented in docs/THREAT_MODEL.md.
        """
        import os
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
