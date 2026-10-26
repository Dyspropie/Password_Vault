"""Settings dialog for application configuration, backups, CSV import/export, and security."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING, Any

from ui.change_password_dialog import ChangePasswordDialog
from ui.widgets import center_window, run_worker_task
from vault.errors import BackupError

if TYPE_CHECKING:
    from ui.app import VaultApp


class BackupPasswordDialog(tk.Toplevel):
    """Small modal dialog to prompt for a backup password."""

    def __init__(self, parent: tk.Misc, title: str, prompt: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        self.password: str | None = None

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=prompt, wraplength=340).pack(anchor="w", pady=(0, 10))

        self.pwd_var = tk.StringVar()
        self.entry = ttk.Entry(frame, textvariable=self.pwd_var, show="*", width=32)
        self.entry.pack(fill="x", pady=(0, 12))

        btn_box = ttk.Frame(frame)
        btn_box.pack(fill="x")

        ttk.Button(btn_box, text="Cancel", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(btn_box, text="OK", command=self._on_ok).pack(side="right")

        self.entry.bind("<Return>", lambda _: self._on_ok())
        self.entry.bind("<Escape>", lambda _: self.destroy())

        center_window(self, parent, width=380, height=180)
        self.entry.focus_set()
        self.wait_window()

    def _on_ok(self) -> None:
        pwd = self.pwd_var.get().strip()
        if pwd:
            self.password = pwd
            self.destroy()
        else:
            messagebox.showwarning("Password Required", "Please enter a password.", parent=self)


class SettingsDialog(tk.Toplevel):
    """Application preferences and data management dialog."""

    def __init__(self, parent: tk.Misc, app: VaultApp, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self.title("Settings & Preferences")
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        self.app = app
        self.service = app.service

        self._build_ui()
        center_window(self, parent, width=540, height=540)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        # Inactivity & Security Preferences
        pref_box = ttk.LabelFrame(frame, text="Security & Auto-lock", padding=12)
        pref_box.pack(fill="x", pady=(0, 12))

        # Auto-lock minutes
        row1 = ttk.Frame(pref_box)
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Auto-lock after idle minutes (0 to disable):").pack(side="left")
        self.autolock_var = tk.IntVar(value=int(self.service.get_setting("autolock_minutes", 5)))
        self.autolock_spin = ttk.Spinbox(row1, from_=0, to=120, increment=1, textvariable=self.autolock_var, width=6)
        self.autolock_spin.pack(side="right")

        # Clipboard clear seconds
        row2 = ttk.Frame(pref_box)
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Clear clipboard after seconds:").pack(side="left")
        self.clipboard_var = tk.IntVar(value=int(self.service.get_setting("clipboard_clear_seconds", 15)))
        self.clipboard_spin = ttk.Spinbox(
            row2, from_=5, to=300, increment=5, textvariable=self.clipboard_var, width=6
        )
        self.clipboard_spin.pack(side="right")

        # Lock on minimize
        row3 = ttk.Frame(pref_box)
        row3.pack(fill="x", pady=4)
        self.minimize_var = tk.BooleanVar(value=bool(self.service.get_setting("lock_on_minimize", False)))
        ttk.Checkbutton(
            row3, text="Lock vault immediately when window is minimized", variable=self.minimize_var
        ).pack(side="left")

        # Save preferences button
        save_pref_btn = ttk.Button(pref_box, text="Save Preferences", command=self._on_save_preferences)
        save_pref_btn.pack(anchor="e", pady=(6, 0))

        # Master Password Section
        pwd_box = ttk.LabelFrame(frame, text="Master Password", padding=12)
        pwd_box.pack(fill="x", pady=(0, 12))

        ttk.Label(
            pwd_box,
            text="Change the password that encrypts and protects all vault data.",
            wraplength=480,
        ).pack(anchor="w", pady=(0, 6))

        chg_pwd_btn = ttk.Button(pwd_box, text="Change Master Password...", command=self._on_change_password)
        chg_pwd_btn.pack(anchor="w")

        # Data Management & Backups
        data_box = ttk.LabelFrame(frame, text="Data Portability & Backups", padding=12)
        data_box.pack(fill="x", pady=(0, 12))

        btn_grid = ttk.Frame(data_box)
        btn_grid.pack(fill="x")

        self.export_vbak_btn = ttk.Button(btn_grid, text="Export Encrypted Backup (.vbak)...", command=self._on_export_backup)
        self.export_vbak_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=4)

        self.restore_vbak_btn = ttk.Button(btn_grid, text="Restore Encrypted Backup (.vbak)...", command=self._on_restore_backup)
        self.restore_vbak_btn.grid(row=0, column=1, sticky="ew", pady=4)

        self.import_csv_btn = ttk.Button(btn_grid, text="Import CSV (Chrome / Firefox)...", command=self._on_import_csv)
        self.import_csv_btn.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=4)

        self.export_csv_btn = ttk.Button(btn_grid, text="Export Plaintext CSV...", command=self._on_export_csv)
        self.export_csv_btn.grid(row=1, column=1, sticky="ew", pady=4)

        btn_grid.columnconfigure(0, weight=1)
        btn_grid.columnconfigure(1, weight=1)

        # Indeterminate progress bar for worker operations
        self.progress_bar = ttk.Progressbar(frame, mode="determinate")
        self.progress_bar.pack(fill="x", pady=(0, 10))

        # Bottom Bar
        bottom_bar = ttk.Frame(frame)
        bottom_bar.pack(fill="x", side="bottom")

        about_btn = ttk.Button(bottom_bar, text="About", command=self._on_about)
        about_btn.pack(side="left")

        close_btn = ttk.Button(bottom_bar, text="Close", command=self.destroy)
        close_btn.pack(side="right")

    def _on_save_preferences(self) -> None:
        """Save preference values into metadata and update runtime auto-lock monitor."""
        autolock = max(0, self.autolock_var.get())
        cb_clear = max(5, self.clipboard_var.get())
        lock_min = self.minimize_var.get()

        self.service.set_setting("autolock_minutes", autolock)
        self.service.set_setting("clipboard_clear_seconds", cb_clear)
        self.service.set_setting("lock_on_minimize", lock_min)

        self.app.autolock.configure(idle_minutes=autolock, lock_on_minimize=lock_min)
        messagebox.showinfo("Preferences Saved", "Settings updated successfully.", parent=self)

    def _on_change_password(self) -> None:
        """Open master password change dialog."""
        ChangePasswordDialog(self, self.service)

    def _on_export_backup(self) -> None:
        """Prompt for destination and password, then export encrypted .vbak in worker thread."""
        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Export Encrypted Backup",
            defaultextension=".vbak",
            filetypes=[("Vault Backup Files", "*.vbak")],
        )
        if not dest:
            return

        dlg = BackupPasswordDialog(
            self,
            title="Backup Encryption Password",
            prompt="Choose a password to encrypt this backup file:",
        )
        if not dlg.password:
            return

        def task() -> None:
            self.service.export_backup(dlg.password, dest)

        def on_success(_: Any) -> None:
            messagebox.showinfo("Backup Complete", f"Backup successfully exported to:\n{dest}", parent=self)

        def on_error(exc: Exception) -> None:
            messagebox.showerror("Backup Failed", f"Could not create backup: {exc}", parent=self)

        run_worker_task(
            root=self,
            task_fn=task,
            on_success=on_success,
            on_error=on_error,
            progress_bar=self.progress_bar,
            buttons=[self.export_vbak_btn, self.restore_vbak_btn],
        )

    def _on_restore_backup(self) -> None:
        """Prompt for backup file and password, then restore entries in worker thread."""
        src = filedialog.askopenfilename(
            parent=self,
            title="Select Encrypted Backup File",
            filetypes=[("Vault Backup Files", "*.vbak")],
        )
        if not src:
            return

        dlg = BackupPasswordDialog(
            self,
            title="Enter Backup Password",
            prompt="Enter the password used to encrypt this backup:",
        )
        if not dlg.password:
            return

        def task() -> tuple[int, int]:
            return self.service.import_backup(dlg.password, src)

        def on_success(counts: tuple[int, int]) -> None:
            imported, skipped = counts
            msg = f"Backup restore finished.\n\nEntries imported: {imported}\nEntries skipped (duplicate): {skipped}"
            messagebox.showinfo("Restore Complete", msg, parent=self)
            self.app.refresh_entries()

        def on_error(exc: Exception) -> None:
            messagebox.showerror("Restore Failed", f"Restore error: {exc}", parent=self)

        run_worker_task(
            root=self,
            task_fn=task,
            on_success=on_success,
            on_error=on_error,
            progress_bar=self.progress_bar,
            buttons=[self.export_vbak_btn, self.restore_vbak_btn],
        )

    def _on_import_csv(self) -> None:
        """Import passwords from Chrome or Firefox CSV file."""
        src = filedialog.askopenfilename(
            parent=self,
            title="Select CSV Password File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not src:
            return

        try:
            imported, skipped = self.service.import_csv(src)
            msg = f"CSV import finished.\n\nEntries imported: {imported}\nEntries skipped (duplicate): {skipped}"
            messagebox.showinfo("Import Complete", msg, parent=self)
            self.app.refresh_entries()
        except BackupError as err:
            messagebox.showerror("CSV Import Error", str(err), parent=self)
        except Exception as err:
            messagebox.showerror("CSV Import Error", f"Failed to import CSV: {err}", parent=self)

    def _on_export_csv(self) -> None:
        """Export passwords to unencrypted CSV after two explicit confirmations."""
        confirm1 = messagebox.askyesno(
            "Security Warning",
            "Exporting to CSV produces an UNENCRYPTED plaintext file.\n\n"
            "Anyone who gains access to this file will be able to read all your usernames and passwords.\n\n"
            "Do you wish to proceed?",
            parent=self,
            icon="warning",
        )
        if not confirm1:
            return

        confirm2 = messagebox.askyesno(
            "Final Confirmation",
            "Are you ABSOLUTELY CERTAIN you want to export your passwords in plain text?\n\n"
            "This action is not recommended for production security.",
            parent=self,
            icon="warning",
        )
        if not confirm2:
            return

        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Export Plaintext CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
        )
        if not dest:
            return

        try:
            self.service.export_csv(dest)
            messagebox.showinfo("Export Successful", f"Passwords exported to:\n{dest}", parent=self)
        except Exception as err:
            messagebox.showerror("Export Failed", f"Could not export CSV: {err}", parent=self)

    def _on_about(self) -> None:
        """Display information dialog about the password vault architecture."""
        about_text = (
            "Password Vault v1.0.0\n\n"
            "A zero-knowledge, 100% offline desktop password manager.\n\n"
            "• Encryption: AES-256 in CBC mode with HMAC-SHA256 (Fernet)\n"
            "• Key Derivation: Scrypt (RFC 7914 compliant)\n"
            "• Local Storage: SQLite 3 with secure delete enabled\n"
            "• Rate Limiting: Exponential backoff on failed unlock attempts\n"
            "• Memory Security: Sensitive keys purged on lock and exit"
        )
        messagebox.showinfo("About Password Vault", about_text, parent=self)
