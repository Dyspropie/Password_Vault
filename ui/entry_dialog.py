"""Dialog for creating and editing password vault entries."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable

from ui.generator_dialog import GeneratorDialog
from ui.widgets import StrengthBar, center_window
from vault.errors import DuplicateEntryError
from vault.service import VaultService


class EntryDialog(tk.Toplevel):
    """Modal dialog for creating or editing a password entry."""

    def __init__(
        self,
        parent: tk.Misc,
        service: VaultService,
        entry_id: int | None = None,
        on_saved: Callable[[], None] | None = None,
        clipboard_clear_seconds: int = 15,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.service = service
        self.entry_id = entry_id
        self.on_saved = on_saved
        self.clipboard_clear_seconds = clipboard_clear_seconds

        mode_title = "Edit Entry" if entry_id is not None else "Add New Entry"
        self.title(mode_title)
        self.transient(parent.winfo_toplevel())
        self.grab_set()

        self.initial_data: dict[str, Any] = {}
        self._categories_map: dict[str, int] = {}

        self._build_ui()
        self._load_categories()

        if entry_id is not None:
            self._load_entry_data(entry_id)
        else:
            self.initial_data = self._get_current_data()

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.bind("<Escape>", lambda _: self._on_cancel())

        center_window(self, parent, width=520, height=580)
        self.site_entry.focus_set()

    def _build_ui(self) -> None:
        """Construct form layout and widgets."""
        main_frame = ttk.Frame(self, padding=16)
        main_frame.pack(fill="both", expand=True)
        main_frame.columnconfigure(1, weight=1)

        # Site (required)
        ttk.Label(main_frame, text="Site / Service *:").grid(row=0, column=0, sticky="w", pady=6)
        self.site_var = tk.StringVar()
        self.site_entry = ttk.Entry(main_frame, textvariable=self.site_var)
        self.site_entry.grid(row=0, column=1, sticky="ew", pady=6, padx=(8, 0))

        # URL
        ttk.Label(main_frame, text="Website URL:").grid(row=1, column=0, sticky="w", pady=6)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(main_frame, textvariable=self.url_var)
        self.url_entry.grid(row=1, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Username / Email
        ttk.Label(main_frame, text="Username / Email:").grid(row=2, column=0, sticky="w", pady=6)
        self.user_var = tk.StringVar()
        self.user_entry = ttk.Entry(main_frame, textvariable=self.user_var)
        self.user_entry.grid(row=2, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Password with generator button
        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=6)
        pwd_box = ttk.Frame(main_frame)
        pwd_box.grid(row=3, column=1, sticky="ew", pady=6, padx=(8, 0))
        pwd_box.columnconfigure(0, weight=1)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(pwd_box, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=0, column=0, sticky="ew")

        self.gen_btn = ttk.Button(pwd_box, text="Generate...", width=11, command=self._open_generator)
        self.gen_btn.grid(row=0, column=1, padx=(6, 0))

        # Show password toggle
        self.show_pwd_var = tk.BooleanVar(value=False)
        self.show_cb = ttk.Checkbutton(
            main_frame, text="Show password", variable=self.show_pwd_var, command=self._toggle_show
        )
        self.show_cb.grid(row=4, column=1, sticky="w", pady=(0, 4), padx=(8, 0))

        # Strength Bar
        ttk.Label(main_frame, text="Strength:").grid(row=5, column=0, sticky="w", pady=4)
        self.strength_bar = StrengthBar(main_frame)
        self.strength_bar.grid(row=5, column=1, sticky="ew", pady=4, padx=(8, 0))

        # Category Combobox (editable)
        ttk.Label(main_frame, text="Category:").grid(row=6, column=0, sticky="w", pady=6)
        self.category_var = tk.StringVar()
        self.cat_combo = ttk.Combobox(main_frame, textvariable=self.category_var)
        self.cat_combo.grid(row=6, column=1, sticky="ew", pady=6, padx=(8, 0))

        # Favorite checkbox
        self.fav_var = tk.BooleanVar(value=False)
        self.fav_cb = ttk.Checkbutton(main_frame, text="Mark as favorite", variable=self.fav_var)
        self.fav_cb.grid(row=7, column=1, sticky="w", pady=(2, 6), padx=(8, 0))

        # Notes multiline text
        ttk.Label(main_frame, text="Notes:").grid(row=8, column=0, sticky="nw", pady=6)
        self.notes_text = tk.Text(main_frame, height=5, wrap="word", font=("Segoe UI", 9))
        self.notes_text.grid(row=8, column=1, sticky="nsew", pady=6, padx=(8, 0))
        main_frame.rowconfigure(8, weight=1)

        # Inline validation / warning label
        self.msg_label = ttk.Label(main_frame, text="", foreground="#d9534f", wraplength=460)
        self.msg_label.grid(row=9, column=0, columnspan=2, sticky="w", pady=(4, 6))

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=10, column=0, columnspan=2, sticky="e", pady=(8, 0))

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self._on_cancel)
        cancel_btn.pack(side="right", padx=(8, 0))

        save_btn = ttk.Button(btn_frame, text="Save Entry", command=self._on_save)
        save_btn.pack(side="right")

        # Key traces
        self.password_var.trace_add("write", lambda *_: self.strength_bar.update_strength(self.password_var.get()))
        self.site_entry.bind("<Return>", lambda _: self._on_save())
        self.url_entry.bind("<Return>", lambda _: self._on_save())
        self.user_entry.bind("<Return>", lambda _: self._on_save())
        self.password_entry.bind("<Return>", lambda _: self._on_save())

    def _toggle_show(self) -> None:
        """Toggle masking of password entry."""
        self.password_entry.configure(show="" if self.show_pwd_var.get() else "*")

    def _load_categories(self) -> None:
        """Populate categories combobox from database."""
        cats = self.service.list_categories()
        names = [c["name"] for c in cats]
        self._categories_map = {c["name"].lower(): c["id"] for c in cats}
        self.cat_combo["values"] = names

    def _load_entry_data(self, entry_id: int) -> None:
        """Load and populate form fields with existing entry data."""
        data = self.service.get_entry_details(entry_id)
        self.site_var.set(data["site"])
        self.url_var.set(data["url"])
        self.user_var.set(data["username"])
        self.password_var.set(data["password"])
        self.category_var.set(data["category_name"])
        self.fav_var.set(data["favorite"])
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.insert("1.0", data["notes"])
        self.initial_data = self._get_current_data()

    def _get_current_data(self) -> dict[str, Any]:
        """Collect current values of all form inputs."""
        return {
            "site": self.site_var.get().strip(),
            "url": self.url_var.get().strip(),
            "username": self.user_var.get().strip(),
            "password": self.password_var.get(),
            "category": self.category_var.get().strip(),
            "favorite": self.fav_var.get(),
            "notes": self.notes_text.get("1.0", tk.END).strip(),
        }

    def _has_unsaved_changes(self) -> bool:
        """Check if any form field has been modified from its initial value."""
        return self._get_current_data() != self.initial_data

    def _open_generator(self) -> None:
        """Open password generator dialog and set generated password upon selection."""
        GeneratorDialog(
            parent=self,
            on_use_password=lambda pwd: self.password_var.set(pwd),
            clipboard_clear_seconds=self.clipboard_clear_seconds,
        )

    def _on_save(self) -> None:
        """Validate input and save or update entry in database."""
        self.msg_label.configure(text="")
        current = self._get_current_data()

        if not current["site"]:
            self.msg_label.configure(text="Site name is required.")
            self.site_entry.focus_set()
            return

        cat_id: int | None = None
        cat_name = current["category"]
        if cat_name:
            cat_id = self.service.get_or_create_category(cat_name)

        try:
            if self.entry_id is None:
                self.service.add_entry(
                    site=current["site"],
                    username=current["username"],
                    password=current["password"],
                    url=current["url"],
                    category_id=cat_id,
                    notes=current["notes"],
                    favorite=current["favorite"],
                )
            else:
                self.service.update_entry(
                    entry_id=self.entry_id,
                    site=current["site"],
                    username=current["username"],
                    password=current["password"],
                    url=current["url"],
                    category_id=cat_id,
                    notes=current["notes"],
                    favorite=current["favorite"],
                )

            if self.on_saved:
                self.on_saved()
            self.destroy()

        except DuplicateEntryError as err:
            self.msg_label.configure(text=str(err))
        except Exception as err:
            self.msg_label.configure(text=f"Failed to save entry: {err}")

    def _on_cancel(self) -> None:
        """Prompt confirmation before discarding unsaved changes."""
        if self._has_unsaved_changes():
            discard = messagebox.askyesno(
                "Unsaved Changes",
                "You have unsaved changes. Are you sure you want to discard them?",
                parent=self,
            )
            if not discard:
                return
        self.destroy()
