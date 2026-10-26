"""Main dashboard view containing the toolbar, entry list, details pane, and status bar."""

from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any

from ui.entry_dialog import EntryDialog
from ui.generator_dialog import GeneratorDialog
from ui.settings_dialog import SettingsDialog
from vault.clipboard import copy_secret

if TYPE_CHECKING:
    from ui.app import VaultApp


class MainWindowFrame(ttk.Frame):
    """Main application workspace after successful unlock."""

    def __init__(self, parent: tk.Misc, app: VaultApp, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self.app = app
        self.service = app.service

        self.selected_entry_id: int | None = None
        self._current_secret_pwd: str = ""
        self._is_password_visible: bool = False
        self._status_timer_id: str | None = None

        self._build_ui()
        self._bind_shortcuts()
        self.refresh_entries()
        self._update_status_tick()

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)

        # 1. Top Toolbar
        toolbar = ttk.Frame(self, padding=(8, 6), relief="groove")
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="➕ Add Entry", command=self._on_add_entry).pack(side="left", padx=2)
        ttk.Button(toolbar, text="✏️ Edit", command=self._on_edit_entry).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🗑️ Delete", command=self._on_delete_entry).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6, pady=2)
        ttk.Button(toolbar, text="🔑 Generator", command=self._on_open_generator).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6, pady=2)
        ttk.Button(toolbar, text="⚙️ Settings", command=self._on_open_settings).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🔒 Lock", command=self.app.lock_vault).pack(side="right", padx=2)

        # 2. Filter & Search Bar
        filter_bar = ttk.Frame(self, padding=(8, 6))
        filter_bar.pack(fill="x")

        ttk.Label(filter_bar, text="Search:").pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(filter_bar, textvariable=self.search_var, width=24)
        self.search_entry.pack(side="left", padx=(0, 12))

        ttk.Label(filter_bar, text="Category:").pack(side="left", padx=(0, 4))
        self.cat_filter_var = tk.StringVar(value="All Categories")
        self.cat_combo = ttk.Combobox(filter_bar, textvariable=self.cat_filter_var, state="readonly", width=18)
        self.cat_combo.pack(side="left", padx=(0, 12))

        self.fav_filter_var = tk.BooleanVar(value=False)
        self.fav_cb = ttk.Checkbutton(
            filter_bar, text="★ Favorites Only", variable=self.fav_filter_var, command=self.refresh_entries
        )
        self.fav_cb.pack(side="left")

        # Search traces
        self.search_var.trace_add("write", lambda *_: self.refresh_entries())
        self.cat_combo.bind("<<ComboboxSelected>>", lambda _: self.refresh_entries())

        # 3. Main Workspace Split (PanedWindow)
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        # Left: Entries List
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=3)

        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical")
        self.tree = ttk.Treeview(
            left_frame,
            columns=("site", "username", "category", "updated"),
            show="headings",
            selectmode="browse",
            yscrollcommand=tree_scroll.set,
        )
        tree_scroll.config(command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree.heading("site", text="Site / Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("category", text="Category")
        self.tree.heading("updated", text="Updated")

        self.tree.column("site", width=160, anchor="w")
        self.tree.column("username", width=130, anchor="w")
        self.tree.column("category", width=90, anchor="w")
        self.tree.column("updated", width=110, anchor="w")

        # Empty state message overlay
        self.empty_label = ttk.Label(
            left_frame,
            text="No entries found.\nClick 'Add Entry' or press Ctrl+N to add your first password.",
            font=("Segoe UI", 10),
            justify="center",
            foreground="#777777",
        )

        # Right: Detail Pane
        self.detail_frame = ttk.LabelFrame(paned, text="Entry Details", padding=12)
        paned.add(self.detail_frame, weight=2)
        self._build_detail_pane()

        # 4. Bottom Status Bar
        self.status_bar = ttk.Frame(self, padding=(8, 4), relief="sunken")
        self.status_bar.pack(fill="x", side="bottom")

        self.count_label = ttk.Label(self.status_bar, text="Entries: 0")
        self.count_label.pack(side="left")

        self.autolock_label = ttk.Label(self.status_bar, text="Auto-lock: Active")
        self.autolock_label.pack(side="right")

        # Treeview events & Context Menu
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_selection_changed)
        self.tree.bind("<Double-1>", lambda _: self._on_edit_entry())
        self._build_context_menu()

    def _build_detail_pane(self) -> None:
        """Construct the detail panel widgets."""
        self.detail_frame.columnconfigure(1, weight=1)

        # Site Title
        self.detail_site_label = ttk.Label(self.detail_frame, text="", font=("Segoe UI", 13, "bold"))
        self.detail_site_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # URL with Open button
        ttk.Label(self.detail_frame, text="URL:").grid(row=1, column=0, sticky="w", pady=4)
        url_row = ttk.Frame(self.detail_frame)
        url_row.grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 0))
        url_row.columnconfigure(0, weight=1)

        self.url_display = ttk.Label(url_row, text="", foreground="#0066cc", cursor="hand2")
        self.url_display.grid(row=0, column=0, sticky="w")
        self.url_open_btn = ttk.Button(url_row, text="Open", width=6, command=self._on_open_url)
        self.url_open_btn.grid(row=0, column=1, padx=(6, 0))

        # Username with Copy button
        ttk.Label(self.detail_frame, text="Username:").grid(row=2, column=0, sticky="w", pady=4)
        user_row = ttk.Frame(self.detail_frame)
        user_row.grid(row=2, column=1, sticky="ew", pady=4, padx=(8, 0))
        user_row.columnconfigure(0, weight=1)

        self.user_display = ttk.Label(user_row, text="", font=("Segoe UI", 9, "bold"))
        self.user_display.grid(row=0, column=0, sticky="w")
        self.copy_user_btn = ttk.Button(user_row, text="Copy", width=6, command=self._on_copy_username)
        self.copy_user_btn.grid(row=0, column=1, padx=(6, 0))

        # Password with Show and Copy buttons
        ttk.Label(self.detail_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=4)
        pwd_row = ttk.Frame(self.detail_frame)
        pwd_row.grid(row=3, column=1, sticky="ew", pady=4, padx=(8, 0))
        pwd_row.columnconfigure(0, weight=1)

        self.pwd_display = ttk.Label(pwd_row, text="", font=("Consolas", 10))
        self.pwd_display.grid(row=0, column=0, sticky="w")

        self.show_pwd_btn = ttk.Button(pwd_row, text="Show", width=6, command=self._toggle_password_visibility)
        self.show_pwd_btn.grid(row=0, column=1, padx=(6, 0))

        self.copy_pwd_btn = ttk.Button(pwd_row, text="Copy", width=6, command=self._on_copy_password)
        self.copy_pwd_btn.grid(row=0, column=2, padx=(4, 0))

        # Category & Favorite
        ttk.Label(self.detail_frame, text="Category:").grid(row=4, column=0, sticky="w", pady=4)
        self.cat_display = ttk.Label(self.detail_frame, text="")
        self.cat_display.grid(row=4, column=1, sticky="w", pady=4, padx=(8, 0))

        # Notes Area
        ttk.Label(self.detail_frame, text="Notes:").grid(row=5, column=0, sticky="nw", pady=4)
        self.notes_display = tk.Text(
            self.detail_frame,
            height=6,
            wrap="word",
            state="disabled",
            bg="#fdfdfd",
            font=("Segoe UI", 9),
        )
        self.notes_display.grid(row=5, column=1, sticky="nsew", pady=4, padx=(8, 0))
        self.detail_frame.rowconfigure(5, weight=1)

        # Timestamps
        self.meta_display = ttk.Label(self.detail_frame, text="", font=("Segoe UI", 8), foreground="#666666")
        self.meta_display.grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))

        self._clear_detail_pane()

    def _clear_detail_pane(self) -> None:
        """Reset detail panel to empty state."""
        self.selected_entry_id = None
        self._current_secret_pwd = ""
        self._is_password_visible = False
        self.detail_site_label.configure(text="")
        self.url_display.configure(text="")
        self.user_display.configure(text="")
        self.pwd_display.configure(text="")
        self.show_pwd_btn.configure(text="Show")
        self.cat_display.configure(text="")
        self.notes_display.configure(state="normal")
        self.notes_display.delete("1.0", tk.END)
        self.notes_display.configure(state="disabled")
        self.meta_display.configure(text="")

    def _build_context_menu(self) -> None:
        """Create right-click popup context menu for Treeview rows."""
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy Username", command=self._on_copy_username)
        self.menu.add_command(label="Copy Password", command=self._on_copy_password)
        self.menu.add_separator()
        self.menu.add_command(label="Edit Entry", command=self._on_edit_entry)
        self.menu.add_command(label="Toggle Favorite", command=self._on_toggle_favorite)
        self.menu.add_command(label="Delete Entry", command=self._on_delete_entry)

        def show_menu(event: Any) -> None:
            row_id = self.tree.identify_row(event.y)
            if row_id:
                self.tree.selection_set(row_id)
                self.menu.post(event.x_root, event.y_root)

        self.tree.bind("<Button-3>", show_menu)

    def _bind_shortcuts(self) -> None:
        """Bind application keyboard shortcuts."""
        root = self.winfo_toplevel()
        root.bind("<Control-n>", lambda _: self._on_add_entry())
        root.bind("<Control-f>", lambda _: self.search_entry.focus_set())
        root.bind("<Control-l>", lambda _: self.app.lock_vault())
        root.bind("<Delete>", lambda _: self._on_delete_entry())
        root.bind("<Return>", lambda _: self._on_edit_entry())

    def refresh_categories_dropdown(self) -> None:
        """Update category options in the filter combobox."""
        current_selection = self.cat_filter_var.get()
        cats = self.service.list_categories()
        options = ["All Categories"] + [c["name"] for c in cats]
        self.cat_combo["values"] = options
        if current_selection not in options:
            self.cat_filter_var.set("All Categories")

    def refresh_entries(self) -> None:
        """Query service for filtered entries and refresh the Treeview."""
        self.refresh_categories_dropdown()

        search = self.search_var.get()
        cat_selection = self.cat_filter_var.get()
        fav_only = self.fav_filter_var.get()

        cat_id: int | None = None
        if cat_selection and cat_selection != "All Categories":
            for c in self.service.list_categories():
                if c["name"] == cat_selection:
                    cat_id = c["id"]
                    break

        entries = self.service.list_entries(search=search, category_id=cat_id, favorites_only=fav_only)

        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        for entry in entries:
            site_display = f"★ {entry['site']}" if entry["favorite"] else entry["site"]
            updated_display = entry["updated_at"][:10] if entry.get("updated_at") else ""
            self.tree.insert(
                "",
                "end",
                iid=str(entry["id"]),
                values=(
                    site_display,
                    entry["username"] or "",
                    entry["category_name"] or "",
                    updated_display,
                ),
            )

        # Manage empty state view
        if not entries:
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
            self._clear_detail_pane()
        else:
            self.empty_label.place_forget()

        self.count_label.configure(text=f"Showing: {len(entries)} entries")

    def _on_tree_selection_changed(self, event: Any = None) -> None:
        """Handle row selection: fetch secret details and reset masked display."""
        selected = self.tree.selection()
        if not selected:
            self._clear_detail_pane()
            return

        entry_id = int(selected[0])
        self.selected_entry_id = entry_id

        # Always reset password to masked upon selection change
        self._is_password_visible = False
        self.show_pwd_btn.configure(text="Show")

        try:
            details = self.service.get_entry_details(entry_id)
            self._current_secret_pwd = details["password"]

            site_text = f"★ {details['site']}" if details["favorite"] else details["site"]
            self.detail_site_label.configure(text=site_text)
            self.url_display.configure(text=details["url"] or "—")
            self.user_display.configure(text=details["username"] or "—")
            self.pwd_display.configure(text="●●●●●●●●" if details["password"] else "—")
            self.cat_display.configure(text=details["category_name"] or "None")

            self.notes_display.configure(state="normal")
            self.notes_display.delete("1.0", tk.END)
            self.notes_display.insert("1.0", details["notes"])
            self.notes_display.configure(state="disabled")

            created = details["created_at"][:19].replace("T", " ") if details["created_at"] else "—"
            updated = details["updated_at"][:19].replace("T", " ") if details["updated_at"] else "—"
            self.meta_display.configure(text=f"Created: {created} UTC  •  Updated: {updated} UTC")

        except Exception as err:
            self._clear_detail_pane()

    def _toggle_password_visibility(self) -> None:
        """Toggle secret password reveal/mask in detail pane."""
        if not self._current_secret_pwd:
            return

        self._is_password_visible = not self._is_password_visible
        if self._is_password_visible:
            self.pwd_display.configure(text=self._current_secret_pwd)
            self.show_pwd_btn.configure(text="Hide")
        else:
            self.pwd_display.configure(text="●●●●●●●●")
            self.show_pwd_btn.configure(text="Show")

    def _on_copy_username(self) -> None:
        """Copy current username to clipboard."""
        if self.selected_entry_id:
            user = self.user_display.cget("text")
            if user and user != "—":
                secs = int(self.service.get_setting("clipboard_clear_seconds", 15))
                copy_secret(self, user, seconds=secs)

    def _on_copy_password(self) -> None:
        """Copy current password to clipboard."""
        if self.selected_entry_id and self._current_secret_pwd:
            secs = int(self.service.get_setting("clipboard_clear_seconds", 15))
            copy_secret(self, self._current_secret_pwd, seconds=secs)

    def _on_open_url(self) -> None:
        """Launch URL in system web browser."""
        url = self.url_display.cget("text")
        if url and url != "—":
            if not (url.startswith("http://") or url.startswith("https://")):
                url = f"https://{url}"
            webbrowser.open(url)

    def _on_add_entry(self) -> None:
        """Open EntryDialog in create mode."""
        secs = int(self.service.get_setting("clipboard_clear_seconds", 15))
        EntryDialog(self, self.service, entry_id=None, on_saved=self.refresh_entries, clipboard_clear_seconds=secs)

    def _on_edit_entry(self) -> None:
        """Open EntryDialog in edit mode for currently selected row."""
        if self.selected_entry_id:
            secs = int(self.service.get_setting("clipboard_clear_seconds", 15))
            EntryDialog(
                self,
                self.service,
                entry_id=self.selected_entry_id,
                on_saved=self.refresh_entries,
                clipboard_clear_seconds=secs,
            )

    def _on_delete_entry(self) -> None:
        """Prompt confirmation and delete currently selected entry."""
        if not self.selected_entry_id:
            return

        site = self.detail_site_label.cget("text")
        confirmed = messagebox.askyesno(
            "Delete Entry",
            f"Are you sure you want to delete the entry for '{site}'?\n\nThis cannot be undone.",
            parent=self,
            icon="warning",
        )
        if confirmed:
            try:
                self.service.delete_entry(self.selected_entry_id)
                self.refresh_entries()
            except Exception as err:
                messagebox.showerror("Delete Failed", str(err), parent=self)

    def _on_toggle_favorite(self) -> None:
        """Toggle favorite flag on selected row."""
        if self.selected_entry_id:
            self.service.toggle_favorite(self.selected_entry_id)
            self.refresh_entries()

    def _on_open_generator(self) -> None:
        """Open password generator dialog."""
        secs = int(self.service.get_setting("clipboard_clear_seconds", 15))
        GeneratorDialog(self, clipboard_clear_seconds=secs)

    def _on_open_settings(self) -> None:
        """Open application settings dialog."""
        SettingsDialog(self, self.app)

    def _update_status_tick(self) -> None:
        """Periodically update auto-lock countdown timer in status bar."""
        rem = self.app.autolock.get_remaining_seconds()
        if rem > 0:
            mins, secs = divmod(rem, 60)
            self.autolock_label.configure(text=f"Auto-lock in: {mins:02d}:{secs:02d}")
        else:
            self.autolock_label.configure(text="Auto-lock: Inactive")

        self._status_timer_id = self.after(1000, self._update_status_tick)

    def destroy(self) -> None:
        """Clean up background periodic timer upon widget destruction."""
        if self._status_timer_id is not None:
            try:
                self.after_cancel(self._status_timer_id)
            except Exception:
                pass
            self._status_timer_id = None
        super().destroy()
