"""Tab: convert a PFX/P12 file back to PEM files (.crt + .key + chain)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import (
    confirm_unencrypted_key, confirm_warnings, file_row, passwords_match, password_entry,
    pfx_types, status_label, write_pem_set,
)


class ConvertTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        f = self
        f.columnconfigure(1, weight=1)
        ttk.Label(
            f,
            text=_(
                "Convert a .pfx / .p12 file (for example exported from IIS) to PEM files for nginx, Apache etc.:\n"
                "<name>.crt, <name>.key and - if the PFX contains a chain - <name>-chain.crt and <name>-fullchain.crt."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.v_pfx = tk.StringVar()
        self.v_pfxpw = tk.StringVar()
        self.v_out = tk.StringVar()
        self.v_out2 = tk.StringVar()

        file_row(f, 1, _("PFX file (.pfx/.p12):"), self.v_pfx, pfx_types())
        ttk.Label(f, text=_("PFX password:")).grid(row=2, column=0, sticky="w", pady=3)
        password_entry(f, self.v_pfxpw, 28).grid(row=2, column=1, sticky="w", padx=6)

        ttk.Separator(f).grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(f, text=_("New key password (optional):")).grid(row=4, column=0, sticky="w", pady=3)
        password_entry(f, self.v_out, 28).grid(row=4, column=1, sticky="w", padx=6)
        ttk.Label(f, text=_("Repeat:")).grid(row=5, column=0, sticky="w", pady=3)
        password_entry(f, self.v_out2, 28).grid(row=5, column=1, sticky="w", padx=6)
        ttk.Label(
            f,
            text=_("Leave empty for an unencrypted key, which most web servers require."),
            foreground="gray",
        ).grid(row=6, column=1, columnspan=2, sticky="w", padx=6)

        ttk.Button(f, text=_("Convert to CRT + KEY..."), command=self.convert).grid(
            row=7, column=0, sticky="w", pady=10
        )
        self.status = tk.StringVar()
        status_label(f, self.status, 8, 3)

    def unsaved(self) -> str | None:
        return None

    def clear(self) -> None:
        for v in (self.v_pfxpw, self.v_out, self.v_out2):
            v.set("")
        self.status.set("")

    def convert(self) -> None:
        if not self.v_pfx.get():
            messagebox.showerror(_("Error"), _("Select a PFX file."))
            return
        if not passwords_match(self.v_out.get(), self.v_out2.get()):
            return
        if not self.v_out.get() and not confirm_unencrypted_key():
            return
        try:
            data = Path(self.v_pfx.get()).read_bytes()
            bundle = csrgen.bundle_from_pfx(data, self.v_pfxpw.get())
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        except OSError as exc:
            messagebox.showerror(_("Error"), _("Could not read file: {err}").format(err=exc))
            return
        if not confirm_warnings(bundle.warnings):
            return
        msg = write_pem_set(csrgen.pem_files(bundle, self.v_out.get()), Path(self.v_pfx.get()).stem)
        if msg:
            self.status.set(msg)
            self.clear_passwords()

    def clear_passwords(self) -> None:
        for v in (self.v_pfxpw, self.v_out, self.v_out2):
            v.set("")
