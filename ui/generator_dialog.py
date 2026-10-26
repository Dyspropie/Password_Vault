"""Password generator dialog with interactive configuration and live preview."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from ui.widgets import center_window
from vault.clipboard import copy_secret
from vault.errors import GeneratorError
from vault.generator import generate_password
from vault.strength import calculate_strength


class GeneratorDialog(tk.Toplevel):
    """Modal dialog for generating cryptographically secure passwords."""

    def __init__(
        self,
        parent: tk.Misc,
        on_use_password: Callable[[str], None] | None = None,
        clipboard_clear_seconds: int = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.title("Password Generator")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        self.on_use_password = on_use_password
        self.clipboard_clear_seconds = clipboard_clear_seconds
        self.current_password: str = ""

        # Outer padding frame
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        # Preview Entry
        preview_frame = ttk.LabelFrame(frame, text="Generated Password", padding=10)
        preview_frame.pack(fill="x", pady=(0, 12))

        self.preview_var = tk.StringVar()
        self.preview_entry = ttk.Entry(
            preview_frame,
            textvariable=self.preview_var,
            font=("Consolas", 13),
            justify="center",
        )
        self.preview_entry.pack(fill="x", pady=(0, 4))

        # Entropy & Strength Label
        self.info_label = ttk.Label(preview_frame, text="", font=("Segoe UI", 9))
        self.info_label.pack(anchor="center")

        # Configuration Options
        opts_frame = ttk.LabelFrame(frame, text="Options", padding=10)
        opts_frame.pack(fill="x", pady=(0, 12))

        # Length slider & value
        length_row = ttk.Frame(opts_frame)
        length_row.pack(fill="x", pady=(0, 8))

        ttk.Label(length_row, text="Length:").pack(side="left")
        self.length_label = ttk.Label(length_row, text="20", width=4, anchor="e")
        self.length_label.pack(side="right")

        self.length_var = tk.IntVar(value=20)
        self.length_slider = ttk.Scale(
            length_row,
            from_=8,
            to=64,
            variable=self.length_var,
            orient="horizontal",
            command=self._on_slider_moved,
        )
        self.length_slider.pack(side="left", fill="x", expand=True, padx=8)

        # Character set checkboxes
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.lookalikes_var = tk.BooleanVar(value=False)

        cb_grid = ttk.Frame(opts_frame)
        cb_grid.pack(fill="x")

        ttk.Checkbutton(
            cb_grid, text="Lowercase (a-z)", variable=self.lower_var, command=self.generate
        ).grid(row=0, column=0, sticky="w", pady=2, padx=(0, 16))
        ttk.Checkbutton(
            cb_grid, text="Uppercase (A-Z)", variable=self.upper_var, command=self.generate
        ).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Checkbutton(
            cb_grid, text="Digits (0-9)", variable=self.digits_var, command=self.generate
        ).grid(row=1, column=0, sticky="w", pady=2, padx=(0, 16))
        ttk.Checkbutton(
            cb_grid, text="Symbols (!@#$)", variable=self.symbols_var, command=self.generate
        ).grid(row=1, column=1, sticky="w", pady=2)
        ttk.Checkbutton(
            cb_grid,
            text="Exclude look-alikes (0, O, o, 1, l, I)",
            variable=self.lookalikes_var,
            command=self.generate,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 2))

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(4, 0))

        self.regen_btn = ttk.Button(btn_frame, text="Regenerate", command=self.generate)
        self.regen_btn.pack(side="left", padx=(0, 6))

        self.copy_btn = ttk.Button(btn_frame, text="Copy", command=self._on_copy)
        self.copy_btn.pack(side="left")

        self.copy_status_label = ttk.Label(btn_frame, text="", foreground="#2e7d32")
        self.copy_status_label.pack(side="left", padx=8)

        if self.on_use_password is not None:
            self.use_btn = ttk.Button(btn_frame, text="Use Password", command=self._on_use)
            self.use_btn.pack(side="right", padx=(6, 0))

        close_btn = ttk.Button(btn_frame, text="Close", command=self.destroy)
        close_btn.pack(side="right")

        # Initial generation and centering
        self.generate()
        center_window(self, parent, width=460, height=380)

    def _on_slider_moved(self, value: Any) -> None:
        """Update length label and trigger password regeneration."""
        int_val = int(float(value))
        self.length_var.set(int_val)
        self.length_label.configure(text=str(int_val))
        self.generate()

    def generate(self) -> None:
        """Generate a new password based on current dialog options."""
        self.copy_status_label.configure(text="")
        try:
            length = self.length_var.get()
            pwd = generate_password(
                length=length,
                use_lower=self.lower_var.get(),
                use_upper=self.upper_var.get(),
                use_digits=self.digits_var.get(),
                use_symbols=self.symbols_var.get(),
                exclude_lookalikes=self.lookalikes_var.get(),
            )
            self.current_password = pwd
            self.preview_var.set(pwd)

            res = calculate_strength(pwd)
            self.info_label.configure(
                text=f"Entropy: {res.entropy_bits} bits  •  Strength: {res.label}",
                foreground="#333333",
            )
            self.copy_btn.configure(state="normal")
            if hasattr(self, "use_btn"):
                self.use_btn.configure(state="normal")
        except GeneratorError as err:
            self.current_password = ""
            self.preview_var.set("")
            self.info_label.configure(text=str(err), foreground="#d9534f")
            self.copy_btn.configure(state="disabled")
            if hasattr(self, "use_btn"):
                self.use_btn.configure(state="disabled")

    def _on_copy(self) -> None:
        """Copy current generated password to clipboard."""
        if self.current_password:
            copy_secret(self, self.current_password, seconds=self.clipboard_clear_seconds)
            self.copy_status_label.configure(text="Copied!")
            self.after(2000, lambda: self.copy_status_label.configure(text=""))

    def _on_use(self) -> None:
        """Send generated password to caller and close dialog."""
        if self.current_password and self.on_use_password:
            self.on_use_password(self.current_password)
            self.destroy()
