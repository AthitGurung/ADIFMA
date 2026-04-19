from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QPoint
from PyQt5.QtGui import QFont

# Class-level stack to manage stacking of multiple toasts
_active_toasts = []

TOAST_COLORS = {
    "success": {"bg": "#d4edda", "border": "#28a745", "title": "#155724", "icon": "✅"},
    "failed":  {"bg": "#f8d7da", "border": "#dc3545", "title": "#721c24", "icon": "❌"},
    "warning": {"bg": "#fff3cd", "border": "#ffc107", "title": "#856404", "icon": "⚠️"},
    "info":    {"bg": "#cce5ff", "border": "#0078D7", "title": "#004085", "icon": "ℹ️"},
    "critical":{"bg": "#f8d7da", "border": "#8b0000", "title": "#8b0000", "icon": "🔴"},
}

TOAST_WIDTH  = 340
TOAST_HEIGHT = 130  # fixed height per toast
TOAST_MARGIN = 10   # gap between stacked toasts


class ToastNotification(QWidget):
    """
    Rich, stacking toast notification widget.

    Parameters
    ----------
    parent      : parent widget (toast is drawn relative to it)
    title       : first bold line (e.g. event type)
    message     : fallback single-line body (used when detail fields are absent)
    color_hex   : accent colour string — overridden when level is supplied
    level       : "success" | "failed" | "warning" | "info" | "critical"
    action      : AD action label shown in the detail grid
    user        : target username
    status      : "Success" / "Failed" / "Warning"
    reason      : reason text (for failures)
    duration_ms : auto-dismiss delay in milliseconds
    """

    def __init__(
        self,
        parent=None,
        title="",
        message="",
        color_hex=None,
        level=None,
        action="",
        user="",
        status="",
        reason="",
        duration_ms=6000,
    ):
        super().__init__(parent)
        self.setWindowFlags(Qt.SubWindow | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.duration_ms = duration_ms

        # Resolve colour scheme
        if level is None:
            # Auto-detect from status or title
            s = status.lower() if status else title.lower()
            if "success" in s:
                level = "success"
            elif "fail" in s or "error" in s or "brute" in s or "lockout" in s:
                level = "failed"
            elif "warning" in s or "warn" in s or "privilege" in s:
                level = "warning"
            elif "critical" in s:
                level = "critical"
            else:
                level = "info"

        scheme = TOAST_COLORS.get(level, TOAST_COLORS["info"])
        bg_color     = scheme["bg"]
        border_color = color_hex if color_hex else scheme["border"]
        title_color  = scheme["title"]
        icon         = scheme["icon"]

        # ---- Layout ----
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border-left: 5px solid {border_color};
                border-top: 1px solid #ccc;
                border-right: 1px solid #ccc;
                border-bottom: 1px solid #ccc;
                border-radius: 6px;
            }}
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 10, 12, 10)
        card_layout.setSpacing(4)

        # Title row
        title_lbl = QLabel(f"{icon}  {title}")
        title_lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        title_lbl.setStyleSheet(f"color: {title_color}; background: transparent; border: none;")
        card_layout.addWidget(title_lbl)

        # Detail grid (action / user / status / reason)
        if any([action, user, status, reason]):
            grid = QHBoxLayout()
            grid.setSpacing(6)

            def _cell(label_txt, value_txt):
                col = QVBoxLayout()
                col.setSpacing(1)
                lbl = QLabel(label_txt)
                lbl.setStyleSheet("color: #555; font-size: 10px; font-weight: bold; background: transparent; border: none;")
                val = QLabel(value_txt or "—")
                val.setStyleSheet(f"color: {title_color}; font-size: 11px; background: transparent; border: none;")
                val.setWordWrap(True)
                col.addWidget(lbl)
                col.addWidget(val)
                return col

            grid.addLayout(_cell("ACTION", action))
            grid.addLayout(_cell("USER", user))
            grid.addLayout(_cell("STATUS", status))
            if reason:
                grid.addLayout(_cell("REASON", reason))

            card_layout.addLayout(grid)
        else:
            # Fallback plain message
            msg_lbl = QLabel(message)
            msg_lbl.setWordWrap(True)
            msg_lbl.setStyleSheet(f"color: {title_color}; font-size: 11px; background: transparent; border: none;")
            card_layout.addWidget(msg_lbl)

        outer.addWidget(card)

        self.setFixedSize(TOAST_WIDTH, TOAST_HEIGHT)

        # Auto dismiss
        self._dismiss_timer = QTimer(self)
        self._dismiss_timer.setSingleShot(True)
        self._dismiss_timer.timeout.connect(self.fade_out)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_toast(self):
        """Register, position and display this toast."""
        _active_toasts.append(self)
        self._restack_all()
        self.show()
        self._dismiss_timer.start(self.duration_ms)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _restack_all():
        """Recompute Y positions so toasts stack without overlap."""
        if not _active_toasts:
            return
        # Use the first active toast's parent rect as reference
        ref = _active_toasts[0]
        if ref.parent():
            parent_rect = ref.parent().rect()
        else:
            return

        bottom_y = parent_rect.height() - TOAST_MARGIN
        for toast in reversed(_active_toasts):
            x = parent_rect.width() - TOAST_WIDTH - TOAST_MARGIN
            y = bottom_y - TOAST_HEIGHT
            toast.move(x, y)
            bottom_y = y - TOAST_MARGIN

    def fade_out(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(400)
        self.anim.setStartValue(1.0)
        self.anim.setEndValue(0.0)
        self.anim.finished.connect(self._cleanup)
        self.anim.start()

    def _cleanup(self):
        if self in _active_toasts:
            _active_toasts.remove(self)
        ToastNotification._restack_all()
        self.close()
