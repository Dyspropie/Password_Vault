"""Login and unlock view with rate-limiting countdown and worker threading."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from ui.widgets import run_worker_task

if TYPE_CHECKING:
    from ui.app import VaultApp


class LoginFrame(ttk.Frame):
    """View displayed to authenticate the user and unlock an existing vault."""

    def __init__(self, parent: tk.Misc, app: VaultApp, **kwargs: Any) -> None:
        super().__init__(parent, padding=24, **kwargs)
        self.app = app

        self.columnconfigure(0, weight=1)

        # Header
        title_label = ttk.Label(self, text="Unlock Vault", font=("Segoe UI", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 6), sticky="w")

        desc_label = ttk.Label(
            self,
            text="Enter your master password to decrypt and access your passwords.",
            wraplength=420,
        )
        desc_label.grid(row=1, column=0, pady=(0, 16), sticky="w")

        # Form container
        form_frame = ttk.Frame(self)
        form_frame.grid(row=2, column=0, sticky="ew")
        form_frame.columnconfigure(1, weight=1)

        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, sticky="w", pady=6)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Show password toggle
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_cb = ttk.Checkbutton(
            form_frame,
            text="Show password",
            variable=self.show_password_var,
            command=self._toggle_show,
        )
        self.show_cb.grid(row=1, column=1, sticky="w", pady=(2, 8), padx=(8, 0))

        # Inline error and countdown label
        self.error_label = ttk.Label(self, text="", foreground="#d9534f", wraplength=420)
        self.error_label.grid(row=3, column=0, sticky="w", pady=(0, 8))

        # Indeterminate progress bar
        self.progress_bar = ttk.Progressbar(self, mode="determinate")
        self.progress_bar.grid(row=4, column=0, sticky="ew", pady=(0, 12))

        # Action button
        self.unlock_btn = ttk.Button(self, text="Unlock", command=self._on_unlock_clicked)
        self.unlock_btn.grid(row=5, column=0, sticky="e")

        # Bind Enter key to unlock
        self.password_entry.bind("<Return>", lambda _: self._on_unlock_clicked())

        self.password_entry.focus_set()
        self._check_retry_delay()

    def _toggle_show(self) -> None:
        """Toggle mask character for password entry."""
        char = "" if self.show_password_var.get() else "*"
        self.password_entry.configure(show=char)

    def _check_retry_delay(self) -> None:
        """Evaluate rate-limiting delay and manage button state and countdown display."""
        remaining = self.app.service.seconds_until_retry()
        if remaining > 0:
            self.unlock_btn.configure(state="disabled")
            self.error_label.configure(
                text=f"Too many failed attempts. Retry unlocked in {remaining}s...",
                foreground="#d9534f",
            )
            self.after(1000, self._check_retry_delay)
        else:
            self.unlock_btn.configure(state="normal")
            if "Too many failed attempts" in self.error_label.cget("text"):
                self.error_label.configure(text="")

    def _on_unlock_clicked(self) -> None:
        """Initiate background worker unlock and key derivation."""
        if self.app.service.seconds_until_retry() > 0:
            self._check_retry_delay()
            return

        pwd = self.password_var.get()
        if not pwd:
            self.error_label.configure(text="Please enter your master password.")
            return

        self.error_label.configure(text="")

        def task() -> None:
            self.app.service.unlock(pwd)

        def on_success(_: Any) -> None:
            self.password_var.set("")
            self.app.on_vault_unlocked()

        def on_error(exc: Exception) -> None:
            self.password_var.set("")
            self.error_label.configure(text=f"Unlock failed: {exc}")
            self._check_retry_delay()

        run_worker_task(
            root=self,
            task_fn=task,
            on_success=on_success,
            on_error=on_error,
            progress_bar=self.progress_bar,
            buttons=[self.unlock_btn, self.show_cb],
        )
