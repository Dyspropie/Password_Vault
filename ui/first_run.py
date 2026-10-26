"""First-run setup view for creating a new password vault."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from ui.widgets import StrengthBar, run_worker_task

if TYPE_CHECKING:
    from ui.app import VaultApp


class FirstRunFrame(ttk.Frame):
    """View displayed when no existing vault is found, prompting master password creation."""

    def __init__(self, parent: tk.Misc, app: VaultApp, **kwargs: Any) -> None:
        super().__init__(parent, padding=24, **kwargs)
        self.app = app

        self.columnconfigure(0, weight=1)

        # Header title and description
        title_label = ttk.Label(self, text="Create Master Password", font=("Segoe UI", 16, "bold"))
        title_label.grid(row=0, column=0, pady=(0, 6), sticky="w")

        desc_text = (
            "Welcome to Password Vault. Your master password encrypts your entire database "
            "using AES-256 (Fernet) with Scrypt key derivation. All processing is 100% offline."
        )
        desc_label = ttk.Label(self, text=desc_text, wraplength=460)
        desc_label.grid(row=1, column=0, pady=(0, 16), sticky="w")

        # Form container
        form_frame = ttk.Frame(self)
        form_frame.grid(row=2, column=0, sticky="ew")
        form_frame.columnconfigure(1, weight=1)

        # Password Entry
        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, sticky="w", pady=6)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=32)
        self.password_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Strength Bar
        ttk.Label(form_frame, text="Strength:").grid(row=1, column=0, sticky="w", pady=4)
        self.strength_bar = StrengthBar(form_frame)
        self.strength_bar.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))

        # Confirm Password Entry
        ttk.Label(form_frame, text="Confirm Password:").grid(row=2, column=0, sticky="w", pady=6)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(form_frame, textvariable=self.confirm_var, show="*", width=32)
        self.confirm_entry.grid(row=2, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Show passwords toggle
        self.show_passwords_var = tk.BooleanVar(value=False)
        self.show_cb = ttk.Checkbutton(
            form_frame,
            text="Show passwords",
            variable=self.show_passwords_var,
            command=self._toggle_show_passwords,
        )
        self.show_cb.grid(row=3, column=1, sticky="w", pady=(2, 8), padx=(8, 0))

        # Requirement and Warning Notes
        req_frame = ttk.Frame(self)
        req_frame.grid(row=3, column=0, sticky="ew", pady=(8, 12))
        ttk.Label(
            req_frame,
            text="• Minimum 12 characters required.\n• Use a combination of uppercase, lowercase, numbers, and symbols.",
            foreground="#555555",
        ).pack(anchor="w")

        # Recovery disclaimer acknowledgment checkbox
        self.ack_var = tk.BooleanVar(value=False)
        self.ack_cb = ttk.Checkbutton(
            self,
            text="I understand there is no recovery if I forget this password.",
            variable=self.ack_var,
            command=self._validate_form,
        )
        self.ack_cb.grid(row=4, column=0, sticky="w", pady=(4, 12))

        # Inline status / validation error message
        self.error_label = ttk.Label(self, text="", foreground="#d9534f", wraplength=460)
        self.error_label.grid(row=5, column=0, sticky="w", pady=(0, 8))

        # Progress bar during key derivation
        self.progress_bar = ttk.Progressbar(self, mode="determinate")
        self.progress_bar.grid(row=6, column=0, sticky="ew", pady=(0, 12))

        # Action button
        self.create_btn = ttk.Button(
            self,
            text="Create Vault",
            state="disabled",
            command=self._on_create_clicked,
        )
        self.create_btn.grid(row=7, column=0, sticky="e")

        # Bind validation triggers
        self.password_var.trace_add("write", lambda *_: self._on_password_changed())
        self.confirm_var.trace_add("write", lambda *_: self._validate_form())

        self.password_entry.focus_set()

    def _toggle_show_passwords(self) -> None:
        """Toggle entry masking between asterisks and plain text."""
        char = "" if self.show_passwords_var.get() else "*"
        self.password_entry.configure(show=char)
        self.confirm_entry.configure(show=char)

    def _on_password_changed(self) -> None:
        """Handle master password input and refresh strength meter."""
        pwd = self.password_var.get()
        self.strength_bar.update_strength(pwd)
        self._validate_form()

    def _validate_form(self) -> None:
        """Check form constraints and enable Create button when valid."""
        pwd = self.password_var.get()
        confirm = self.confirm_var.get()
        ack = self.ack_var.get()

        self.error_label.configure(text="")

        if not pwd:
            self.create_btn.configure(state="disabled")
            return

        if len(pwd) < 12:
            self.error_label.configure(text=f"Password must be at least 12 characters (currently {len(pwd)}).")
            self.create_btn.configure(state="disabled")
            return

        if confirm and pwd != confirm:
            self.error_label.configure(text="Passwords do not match.")
            self.create_btn.configure(state="disabled")
            return

        if pwd == confirm and ack:
            self.create_btn.configure(state="normal")
        else:
            self.create_btn.configure(state="disabled")

    def _on_create_clicked(self) -> None:
        """Trigger worker thread for Scrypt key derivation and vault creation."""
        pwd = self.password_var.get()
        self.error_label.configure(text="")

        def task() -> None:
            self.app.service.create_vault(pwd)

        def on_success(_: Any) -> None:
            self.app.on_vault_unlocked()

        def on_error(exc: Exception) -> None:
            self.error_label.configure(text=f"Error creating vault: {exc}")

        run_worker_task(
            root=self,
            task_fn=task,
            on_success=on_success,
            on_error=on_error,
            progress_bar=self.progress_bar,
            buttons=[self.create_btn, self.show_cb, self.ack_cb],
        )
