"""Main Tkinter application controller managing navigation and lifecycle."""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from ui.first_run import FirstRunFrame
from ui.login import LoginFrame
from ui.main_window import MainWindowFrame
from vault.autolock import AutoLock
from vault.clipboard import clear_clipboard
from vault.service import VaultService


class VaultApp:
    """Main application manager for the Password Vault GUI."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize the application root window, styling, and services."""
        self.root = tk.Tk()
        self.root.title("Password Vault")
        self.root.minsize(860, 560)
        self.root.geometry("920x620")

        self._apply_theme()

        self.service = VaultService(db_path)
        self.current_frame: ttk.Frame | None = None

        self.autolock = AutoLock(
            root=self.root,
            on_lock=self.lock_vault,
            idle_minutes=5,
            lock_on_minimize=False,
        )

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Show initial view immediately so current_frame is populated on construction.
        self.start()

    def _apply_theme(self) -> None:
        """Configure preferred ttk theme (vista on Windows, clam as fallback)."""
        style = ttk.Style(self.root)
        available = style.theme_names()
        if sys.platform == "win32" and "vista" in available:
            style.theme_use("vista")
        elif "clam" in available:
            style.theme_use("clam")

    def _switch_view(self, frame_class: type[ttk.Frame], **kwargs) -> ttk.Frame:
        """Replace current root view frame with a new frame instance."""
        if self.current_frame is not None:
            self.current_frame.destroy()
            self.current_frame = None

        frame = frame_class(self.root, app=self, **kwargs)
        frame.pack(fill="both", expand=True)
        self.current_frame = frame
        return frame

    def start(self) -> None:
        """Determine initial application view based on whether vault database exists."""
        if not self.service.vault_exists():
            self.show_first_run()
        else:
            self.show_login()

    def show_first_run(self) -> None:
        """Display master password setup view."""
        self.autolock.stop()
        self._switch_view(FirstRunFrame)

    def show_login(self) -> None:
        """Display vault authentication unlock view."""
        self.autolock.stop()
        self._switch_view(LoginFrame)

    def show_main(self) -> None:
        """Display main dashboard view and activate auto-lock monitor."""
        autolock_mins = int(self.service.get_setting("autolock_minutes", 5))
        lock_minimize = bool(self.service.get_setting("lock_on_minimize", False))

        self.autolock.configure(idle_minutes=autolock_mins, lock_on_minimize=lock_minimize)
        self.autolock.start()

        self._switch_view(MainWindowFrame)

    def on_vault_unlocked(self) -> None:
        """Handler called upon successful vault creation or unlock."""
        self.show_main()

    def lock_vault(self) -> None:
        """Close any open dialogs, purge sensitive data, and return to login."""
        # Dismiss all child toplevel windows/dialogs
        for child in list(self.root.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass

        clear_clipboard(self.root)
        self.autolock.stop()
        self.service.lock()
        self.show_login()

    def refresh_entries(self) -> None:
        """Trigger entry refresh on main dashboard if active."""
        if isinstance(self.current_frame, MainWindowFrame):
            self.current_frame.refresh_entries()

    def on_closing(self) -> None:
        """Perform secure cleanup on application exit."""
        clear_clipboard(self.root)
        self.autolock.stop()
        self.service.lock()
        self.root.destroy()

    def run(self) -> None:
        """Start the Tkinter event loop (initial view already shown in __init__)."""
        self.root.mainloop()
