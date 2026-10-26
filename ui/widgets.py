"""Reusable Tkinter / TTK UI widgets and background worker utilities."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from vault.strength import calculate_strength


def center_window(window: tk.Toplevel | tk.Tk, parent: tk.Misc | None = None, width: int = 500, height: int = 400) -> None:
    """Center a window on screen or relative to its parent window."""
    window.update_idletasks()
    if parent is not None:
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + max(0, (pw - width) // 2)
        y = py + max(0, (ph - height) // 2)
    else:
        sw = window.winfo_screenwidth()
        sh = window.winfo_screenheight()
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 2)

    window.geometry(f"{width}x{height}+{x}+{y}")


def run_worker_task(
    root: tk.Misc,
    task_fn: Callable[[], Any],
    on_success: Callable[[Any], None],
    on_error: Callable[[Exception], None],
    progress_bar: ttk.Progressbar | None = None,
    buttons: list[ttk.Button | tk.Button] | None = None,
) -> None:
    """Execute a CPU-intensive task in a background worker thread.

    Never touches Tkinter widgets from the background thread. Communicates back
    to the UI thread via queue and root.after polling.

    Args:
        root: Any Tk widget used to schedule after callbacks.
        task_fn: Callable executing in the worker thread.
        on_success: Callback invoked on UI thread with result.
        on_error: Callback invoked on UI thread with caught exception.
        progress_bar: Optional indeterminate progress bar to animate.
        buttons: Optional list of buttons to disable during task execution.
    """
    if buttons:
        for btn in buttons:
            try:
                btn.configure(state="disabled")
            except Exception:
                pass

    if progress_bar:
        try:
            progress_bar.configure(mode="indeterminate")
            progress_bar.start(10)
        except Exception:
            pass

    q: queue.Queue[tuple[bool, Any]] = queue.Queue()

    def worker() -> None:
        try:
            res = task_fn()
            q.put((True, res))
        except Exception as exc:
            q.put((False, exc))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def poll() -> None:
        try:
            success, payload = q.get_nowait()
        except queue.Empty:
            root.after(50, poll)
            return

        if progress_bar:
            try:
                progress_bar.stop()
                progress_bar.configure(mode="determinate", value=0)
            except Exception:
                pass

        if buttons:
            for btn in buttons:
                try:
                    btn.configure(state="normal")
                except Exception:
                    pass

        if success:
            on_success(payload)
        else:
            on_error(payload)

    root.after(50, poll)


class StrengthBar(ttk.Frame):
    """Visual password strength indicator with colored progress and strength label."""

    def __init__(self, parent: tk.Misc, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)

        self.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(self, orient="horizontal", maximum=100, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=2)

        self.label = ttk.Label(self, text="Password strength", width=14, anchor="w")
        self.label.grid(row=0, column=1, sticky="w", pady=2)

        self._colors = {
            0: "#d9534f",  # Red
            1: "#f0ad4e",  # Orange
            2: "#ec971f",  # Amber
            3: "#5cb85c",  # Light Green
            4: "#2e7d32",  # Dark Green
        }

    def update_strength(self, password: str) -> int:
        """Analyze password strength and update the bar and label.

        Args:
            password: Password string to evaluate.

        Returns:
            Strength score from 0 (very weak) to 4 (strong).
        """
        if not password:
            self.progress.configure(value=0)
            self.label.configure(text="", foreground="black")
            return 0

        res = calculate_strength(password)
        percent = (res.score + 1) * 20  # 20%, 40%, 60%, 80%, 100%
        self.progress.configure(value=percent)

        color = self._colors.get(res.score, "#333333")
        self.label.configure(text=res.label, foreground=color)
        return res.score
