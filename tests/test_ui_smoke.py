"""Smoke tests for the Tkinter UI layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from ui.app import VaultApp


def test_ui_smoke(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Smoke test UI initialization, view rendering, and clean shutdown.

    Skips cleanly if no graphical display is available (e.g. headless CI).
    """
    try:
        import tkinter as tk
        probe = tk.Tk()
        probe.withdraw()
        probe.destroy()
    except Exception as exc:
        pytest.skip(f"GUI display not available: {exc}")

    # 1. First run view smoke test
    app = VaultApp(db_path=test_db_path)
    assert app.root is not None
    assert app.current_frame is not None

    app.root.after(100, app.on_closing)
    app.root.mainloop()

    # 2. Authenticated main dashboard smoke test
    app2 = VaultApp(db_path=test_db_path)
    app2.service.create_vault("MasterPassword123!", kdf_params=fast_kdf)
    app2.service.unlock("MasterPassword123!")
    app2.show_main()
    assert app2.current_frame is not None

    app2.root.after(100, app2.on_closing)
    app2.root.mainloop()
