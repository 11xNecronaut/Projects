"""
Main window — a header bar (brand + theme toggle) above a tabbed
interface: Keys, Protect, Reveal. Holds the single AppState instance
shared across all three views.

The header replaces an earlier plain QMenuBar "View" menu, which
rendered as unstyled floating text with no visual anchor — a menu is
the wrong control for a single binary choice used constantly. A
dedicated toggle button is one click instead of two (open menu, then
pick), and its icon doubles as a status indicator: you can tell which
theme is active at a glance without opening anything.
"""

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QApplication, QWidget, QHBoxLayout,
    QVBoxLayout, QLabel, QPushButton
)

from .app_state import AppState
from .key_manager_view import KeyManagerView
from .encrypt_view import ProtectView
from .decrypt_view import RevealView
from . import themes


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Arcanux")
        self.resize(900, 680)

        self.settings = QSettings("Arcanux", "Arcanux")
        self.app_state = AppState()

        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        central_layout.addWidget(self._build_header())

        tabs = QTabWidget()
        tabs.addTab(KeyManagerView(self.app_state), "Keys")
        tabs.addTab(ProtectView(self.app_state), "Protect")
        tabs.addTab(RevealView(self.app_state), "Reveal")
        central_layout.addWidget(tabs)

        self.setCentralWidget(central)

        self._apply_saved_theme()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("headerBar")
        header.setFixedHeight(52)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 8, 16, 8)

        brand = QLabel("ARCANUX")
        brand.setObjectName("brandLabel")
        layout.addWidget(brand)
        layout.addStretch(1)

        self.theme_toggle_btn = QPushButton(themes.SUN_ICON)
        self.theme_toggle_btn.setObjectName("themeToggle")
        self.theme_toggle_btn.setFixedSize(36, 36)
        self.theme_toggle_btn.setCursor(Qt.PointingHandCursor)
        self.theme_toggle_btn.setToolTip("Switch to dark mode")
        self.theme_toggle_btn.clicked.connect(self._toggle_theme)
        layout.addWidget(self.theme_toggle_btn)

        return header

    def _apply_saved_theme(self):
        saved = self.settings.value("theme", "light")
        self._set_theme(saved, save=False)

    def _toggle_theme(self):
        current = self.settings.value("theme", "light")
        self._set_theme("dark" if current == "light" else "light")

    def _set_theme(self, name: str, save: bool = True):
        qss = themes.DARK_THEME if name == "dark" else themes.LIGHT_THEME
        QApplication.instance().setStyleSheet(qss)

        if name == "dark":
            self.theme_toggle_btn.setText(themes.MOON_ICON)
            self.theme_toggle_btn.setToolTip("Switch to light mode")
        else:
            self.theme_toggle_btn.setText(themes.SUN_ICON)
            self.theme_toggle_btn.setToolTip("Switch to dark mode")

        if save:
            self.settings.setValue("theme", name)
