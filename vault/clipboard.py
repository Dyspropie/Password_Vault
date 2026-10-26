"""Clipboard management with automatic expiration and sensitive data clearing."""

from __future__ import annotations

from typing import Any

_generation: int = 0
_timer_id: str | None = None
_copied_text: str | None = None


def copy_secret(root: Any, text: str, seconds: int = 15) -> None:
    """Copy sensitive text to clipboard and schedule automatic clearing.

    Clears the clipboard after `seconds` only if the clipboard still contains
    the exact copied text. Cancels any previously scheduled clear timer.

    Args:
        root: The Tk root or window instance providing after and clipboard APIs.
        text: Secret text to copy to the clipboard.
        seconds: Delay in seconds before clearing clipboard (default 15).
    """
    global _generation, _timer_id, _copied_text

    _generation += 1
    current_generation = _generation

    if _timer_id is not None:
        try:
            root.after_cancel(_timer_id)
        except Exception:
            pass
        _timer_id = None

    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        _copied_text = text
    except Exception:
        return

    def _scheduled_clear() -> None:
        global _timer_id, _copied_text
        if _generation == current_generation:
            try:
                current_value = root.clipboard_get()
                if current_value == text:
                    root.clipboard_clear()
            except Exception:
                pass
            _timer_id = None
            _copied_text = None

    _timer_id = root.after(int(seconds * 1000), _scheduled_clear)


def clear_clipboard(root: Any) -> None:
    """Immediately clear the clipboard and cancel any pending clear timers.

    Called during vault locking or application shutdown.

    Args:
        root: The Tk root or window instance.
    """
    global _generation, _timer_id, _copied_text

    _generation += 1

    if _timer_id is not None and root is not None:
        try:
            root.after_cancel(_timer_id)
        except Exception:
            pass
        _timer_id = None

    if root is not None:
        try:
            root.clipboard_clear()
        except Exception:
            pass

    _copied_text = None
