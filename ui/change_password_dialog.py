"""Dialog for changing the vault master password with full re-encryption."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from ui.widgets import StrengthBar, center_window, run_worker_task
from vault.service import VaultService


class ChangePasswordDialog(tk.Toplevel):
    """Modal dialog to securely change the master password and re-encrypt all entries."""

    def __init__(self, parent: tk.Misc, service: VaultService, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self.title("Change Master Password")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        self.service = service

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        # Old password
        ttk.Label(frame, text="Current Password:").grid(row=0, column=0, sticky="w", pady=6)
        self.old_var = tk.StringVar()
        self.old_entry = ttk.Entry(frame, textvariable=self.old_var, show="*", width=30)
        self.old_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=(8, 0))

        # New password
        ttk.Label(frame, text="New Password:").grid(row=1, column=0, sticky="w", pady=6)
        self.new_var = tk.StringVar()
        self.new_entry = ttk.Entry(frame, textvariable=self.new_var, show="*", width=30)
        self.new_entry.grid(row=1, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Strength Bar
        ttk.Label(frame, text="Strength:").grid(row=2, column=0, sticky="w", pady=4)
        self.strength_bar = StrengthBar(frame)
        self.strength_bar.grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))

        # Confirm new password
        ttk.Label(frame, text="Confirm New:").grid(row=3, column=0, sticky="w", pady=6)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(frame, textvariable=self.confirm_var, show="*", width=30)
        self.confirm_entry.grid(row=3, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Show passwords toggle
        self.show_var = tk.BooleanVar(value=False)
        self.show_cb = ttk.Checkbutton(
            frame,
            text="Show passwords",
            variable=self.show_var,
            command=self._toggle_show,
        )
        self.show_cb.grid(row=4, column=1, sticky="w", pady=(2, 8), padx=(8, 0))

        # Requirement info
        ttk.Label(
            frame,
            text="• Minimum 12 characters required.\n• All existing entries will be re-encrypted.",
            foreground="#555555",
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 10))

        # Status / error / success label
        self.msg_label = ttk.Label(frame, text="", wraplength=380)
        self.msg_label.grid(row=6, column=0, columnspan=2, sticky="w", pady=(0, 8))

        # Progress bar
        self.progress_bar = ttk.Progressbar(frame, mode="determinate")
        self.progress_bar.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 12))

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=8, column=0, columnspan=2, sticky="e")

        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.destroy)
        self.cancel_btn.pack(side="right", padx=(8, 0))

        self.change_btn = ttk.Button(
            btn_frame,
            text="Change Password",
            command=self._on_change_clicked,
        )
        self.change_btn.pack(side="right")

        # Traces & Key bindings
        self.new_var.trace_add("write", lambda *_: self.strength_bar.update_strength(self.new_var.get()))
        self.bind("<Return>", lambda _: self._on_change_clicked())
        self.bind("<Escape>", lambda _: self.destroy())

        self.old_entry.focus_set()
        center_window(self, parent, width=480, height=430)

    def _toggle_show(self) -> None:
        """Toggle masking on all password input fields."""
        char = "" if self.show_var.get() else "*"
        self.old_entry.configure(show=char)
        self.new_entry.configure(show=char)
        self.confirm_entry.configure(show=char)

    def _on_change_clicked(self) -> None:
        """Validate input and run background worker re-encryption."""
        old_pwd = self.old_var.get()
        new_pwd = self.new_var.get()
        confirm_pwd = self.confirm_var.get()

        self.msg_label.configure(text="", foreground="#d9534f")

        if not old_pwd:
            self.msg_label.configure(text="Current password is required.")
            return

        if len(new_pwd) < 12:
            self.msg_label.configure(text="New password must be at least 12 characters.")
            return

        if new_pwd != confirm_pwd:
            self.msg_label.configure(text="New passwords do not match.")
            return

        if new_pwd == old_pwd:
            self.msg_label.configure(text="New password cannot be the same as current password.")
            return

        def task() -> None:
            self.service.change_master_password(old_pwd, new_pwd)

        def on_success(_: Any) -> None:
            self.msg_label.configure(
                text="Master password changed and all entries re-encrypted successfully!",
                foreground="#2e7d32",
            )
            self.change_btn.configure(state="disabled")
            self.after(1600, self.destroy)

        def on_error(exc: Exception) -> None:
            self.msg_label.configure(text=f"Failed to change password: {exc}", foreground="#d9534f")

        run_worker_task(
            root=self,
            task_fn=task,
            on_success=on_success,
            on_error=on_error,
            progress_bar=self.progress_bar,
            buttons=[self.change_btn, self.cancel_btn, self.show_cb],
        )
