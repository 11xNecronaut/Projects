"""
Arcanux entry point.

Run with:  python -m src.main
(from the project root, with dependencies from requirements.txt installed)
"""

import sys

from PySide6.QtWidgets import QApplication

from src.gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Arcanux")
    app.setStyle("Fusion")  # consistent base look across platforms for the QSS theme on top
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
