"""Inactivity tracking and automatic vault locking."""

from __future__ import annotations

import time
from typing import Any, Callable


class AutoLock:
    """Monitors user interactions and triggers a callback upon inactivity or minimization."""

    def __init__(
        self,
        root: Any,
        on_lock: Callable[[], None],
        idle_minutes: int = 5,
        lock_on_minimize: bool = False,
    ) -> None:
        """Initialize AutoLock monitor.

        Args:
            root: Tk root window instance.
            on_lock: Callback invoked when auto-lock conditions trigger.
            idle_minutes: Number of idle minutes before locking (0 disables timer).
            lock_on_minimize: Whether to lock immediately when root window is minimized.
        """
        self.root = root
        self.on_lock = on_lock
        self.idle_minutes = idle_minutes
        self.lock_on_minimize = lock_on_minimize
        self.last_activity = time.monotonic()
        self._timer_id: str | None = None
        self._enabled = False

        self._bind_events()

    def _bind_events(self) -> None:
        """Bind user input events to track activity across the application window."""
        try:
            self.root.bind_all("<Key>", self._on_user_activity, add="+")
            self.root.bind_all("<Button>", self._on_user_activity, add="+")
            self.root.bind_all("<Motion>", self._on_user_activity, add="+")
            self.root.bind("<Unmap>", self._on_unmap, add="+")
        except Exception:
            pass

    def _on_user_activity(self, event: Any = None) -> None:
        """Record user input timestamp."""
        self.last_activity = time.monotonic()

    def _on_unmap(self, event: Any = None) -> None:
        """Handle root unmap event for optional lock on minimize."""
        if not self._enabled or not self.lock_on_minimize:
            return
        try:
            # Check if root is iconified (minimized)
            if self.root.state() == "iconic":
                self.trigger_lock()
        except Exception:
            pass

    def _schedule_tick(self) -> None:
        """Schedule next periodic idle check via root.after."""
        if not self._enabled:
            return
        self._timer_id = self.root.after(1000, self._check_idle)

    def _check_idle(self) -> None:
        """Evaluate elapsed idle time and trigger lock if threshold exceeded."""
        if not self._enabled:
            return

        if self.idle_minutes > 0:
            elapsed = time.monotonic() - self.last_activity
            if elapsed >= self.idle_minutes * 60:
                self.trigger_lock()
                return

        self._schedule_tick()

    def trigger_lock(self) -> None:
        """Force immediate lock execution."""
        self.stop()
        try:
            self.on_lock()
        except Exception:
            pass

    def start(self) -> None:
        """Enable auto-lock tracking and schedule idle checks."""
        self.stop()
        self._enabled = True
        self.last_activity = time.monotonic()
        self._schedule_tick()

    def stop(self) -> None:
        """Pause auto-lock tracking and cancel pending tick timers."""
        self._enabled = False
        if self._timer_id is not None:
            try:
                self.root.after_cancel(self._timer_id)
            except Exception:
                pass
            self._timer_id = None

    def configure(self, idle_minutes: int, lock_on_minimize: bool) -> None:
        """Update auto-lock configuration settings.

        Args:
            idle_minutes: New idle duration in minutes.
            lock_on_minimize: Whether to lock upon minimization.
        """
        self.idle_minutes = idle_minutes
        self.lock_on_minimize = lock_on_minimize
        self.last_activity = time.monotonic()

    def get_remaining_seconds(self) -> int:
        """Return the number of seconds remaining before auto-lock triggers."""
        if not self._enabled or self.idle_minutes <= 0:
            return 0
        elapsed = time.monotonic() - self.last_activity
        remaining = int((self.idle_minutes * 60) - elapsed)
        return max(0, remaining)
