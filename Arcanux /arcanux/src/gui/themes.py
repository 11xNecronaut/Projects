"""
Light and dark themes for Arcanux.

Color direction, and why: Sarvam AI's public brand guidelines (sarvam.ai/brand)
describe their visual system as "a blue-to-orange spectrum... operating
through continuous transitions in light and tone" rather than fixed
color blocks — explicitly framed as signals of motion, flow, and
responsiveness. That maps unusually well onto what this app actually
needed: the earlier version had one flat indigo doing every job (primary
actions, focus rings, tab highlights) with no sense of state or motion.

Here, blue and orange are given distinct jobs instead of being merged
into one accent: blue anchors structure (titles, focus, selected tab —
"where you are"), orange marks active motion (primary action buttons,
hover states — "what moves next"). The gradient itself appears only on
the two elements that represent user-initiated action: primary buttons
and the theme toggle — consistent with the brand language being about
transitions tied to interaction, not decoration applied everywhere.
"""

_SHARED_QSS_TEMPLATE = """
QWidget {{
    background-color: {bg};
    color: {fg};
    font-family: -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}

QMainWindow {{
    background-color: {bg};
}}

QWidget#headerBar {{
    background-color: {panel_bg};
    border-bottom: 1px solid {border};
}}

QLabel#brandLabel {{
    font-size: 15px;
    font-weight: 700;
    color: {accent_blue};
    letter-spacing: 2px;
}}

QGroupBox {{
    border: 1px solid {border};
    border-radius: 8px;
    margin-top: 14px;
    padding: 14px 10px 10px 10px;
    font-weight: 600;
    background-color: {panel_bg};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: {accent_blue};
}}

QLabel {{
    background: transparent;
}}

QPushButton {{
    background-color: {button_bg};
    color: {fg};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {button_hover};
    border-color: {accent_orange};
}}

QPushButton:pressed {{
    background-color: {accent_orange};
    color: {accent_text};
    border-color: {accent_orange};
}}

QPushButton:disabled {{
    background-color: {panel_bg};
    color: {disabled_fg};
    border-color: {border};
}}

QPushButton#primaryAction {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                 stop:0 {grad_start}, stop:1 {grad_end});
    color: {accent_text};
    border: none;
    font-weight: 600;
    padding: 10px 18px;
}}

QPushButton#primaryAction:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                 stop:0 {grad_start_hover}, stop:1 {grad_end_hover});
}}

QPushButton#primaryAction:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                 stop:0 {grad_end}, stop:1 {grad_start});
}}

QPushButton#primaryAction:disabled {{
    background: {panel_bg};
    color: {disabled_fg};
}}

QPushButton#themeToggle {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                 stop:0 {grad_start}, stop:1 {grad_end});
    color: white;
    border: none;
    border-radius: 18px;
    font-size: 16px;
    padding: 0px;
}}

QPushButton#themeToggle:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                 stop:0 {grad_start_hover}, stop:1 {grad_end_hover});
}}

QLineEdit, QTextEdit {{
    background-color: {input_bg};
    color: {fg};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: {accent_orange};
    selection-color: {accent_text};
}}

QLineEdit:focus, QTextEdit:focus {{
    border: 1px solid {accent_blue};
}}

QTabWidget::pane {{
    border: 1px solid {border};
    border-radius: 8px;
    top: -1px;
    background-color: {bg};
}}

QTabBar::tab {{
    background-color: {panel_bg};
    color: {disabled_fg};
    padding: 9px 20px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {bg};
    color: {accent_blue};
    border: 1px solid {border};
    border-bottom: none;
}}

QTabBar::tab:hover:!selected {{
    color: {fg};
}}

QMessageBox {{
    background-color: {bg};
}}
"""

# Gradient stops shared by both themes — the blue anchors structure,
# the orange marks motion/action, per the brand direction above.
_GRAD_START_LIGHT = "#3a5fe0"
_GRAD_END_LIGHT = "#ff8a3d"
_GRAD_START_LIGHT_HOVER = "#5675e8"
_GRAD_END_LIGHT_HOVER = "#ff9d5c"

_GRAD_START_DARK = "#5b7bff"
_GRAD_END_DARK = "#ffab6b"
_GRAD_START_DARK_HOVER = "#7690ff"
_GRAD_END_DARK_HOVER = "#ffbc8a"

LIGHT_THEME = _SHARED_QSS_TEMPLATE.format(
    bg="#faf9f6",
    fg="#1a1f36",
    panel_bg="#f2f0ea",
    border="#e2ded2",
    input_bg="#ffffff",
    button_bg="#ffffff",
    button_hover="#fff1e6",
    disabled_fg="#9a9588",
    accent_blue="#3a5fe0",
    accent_orange="#ff8a3d",
    accent_text="#ffffff",
    grad_start=_GRAD_START_LIGHT,
    grad_end=_GRAD_END_LIGHT,
    grad_start_hover=_GRAD_START_LIGHT_HOVER,
    grad_end_hover=_GRAD_END_LIGHT_HOVER,
)

DARK_THEME = _SHARED_QSS_TEMPLATE.format(
    bg="#14161f",
    fg="#ecebf5",
    panel_bg="#1d2030",
    border="#2f3346",
    input_bg="#10121b",
    button_bg="#232640",
    button_hover="#2b2f4d",
    disabled_fg="#666a87",
    accent_blue="#7c93ff",
    accent_orange="#ffab6b",
    accent_text="#10121b",
    grad_start=_GRAD_START_DARK,
    grad_end=_GRAD_END_DARK,
    grad_start_hover=_GRAD_START_DARK_HOVER,
    grad_end_hover=_GRAD_END_DARK_HOVER,
)

# The delete-keystore button stays universally red in both themes —
# color-coding a destructive/irreversible action is a safety signal,
# not a branding choice, and it must not get absorbed into the
# blue/orange system where it could read as "just another action."
DESTRUCTIVE_BUTTON_QSS = "QPushButton { color: #d64545; font-weight: 600; }"

# Icons the theme toggle button displays for the currently ACTIVE theme
# (per the brief: pressing into light shows a sun, pressing into dark
# shows a moon — the icon reflects where you are, not where you're going).
SUN_ICON = "☀"
MOON_ICON = "🌙"
