"""
Shared layout helper — fixes a real problem: a QVBoxLayout set directly
on a tab's root widget stretches every child (buttons, group boxes) to
the full window width when the window is maximized. On a 1920px-wide
screen that means buttons three times wider than their text and a
canyon of empty space below. Desktop apps that get this right (Settings
panels, most modern tools) cap content to a comfortable reading width
and center it, letting the background — not the controls — absorb the
extra space.

build_centered_view() sets that pattern up once; every view uses it
instead of putting a QVBoxLayout directly on self.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout


def build_centered_view(parent_widget: QWidget, max_width: int = 760) -> QVBoxLayout:
    """
    Sets parent_widget up with an outer layout containing a centered,
    width-capped content column, anchored to the top. Returns the
    QVBoxLayout that view code should add its actual sections into —
    used exactly like `layout = QVBoxLayout(self)` was before, just
    assign the return value the same way.
    """
    outer = QVBoxLayout(parent_widget)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)

    row = QHBoxLayout()
    row.setContentsMargins(28, 24, 28, 24)
    row.addStretch(1)

    content = QWidget()
    content.setMaximumWidth(max_width)
    content_layout = QVBoxLayout(content)
    content_layout.setSpacing(16)
    content_layout.setContentsMargins(0, 0, 0, 0)

    row.addWidget(content, 0)
    row.addStretch(1)

    outer.addLayout(row)
    outer.addStretch(1)  # absorbs extra vertical space instead of the content stretching

    return content_layout
