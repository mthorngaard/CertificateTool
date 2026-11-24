"""Tab: inspect a certificate or CSR (file or pasted PEM)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import cert_types, file_row, make_output_box, set_text


class InspectTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(1, weight=1)
        ttk.Label(
            self,
            text=_("Show the contents of a certificate (.cer/.crt/.pem/.p7b) or a CSR: subject, SANs, expiry, key, fingerprints."),
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self.v_file = tk.StringVar()
        file_row(self, 1, _("File:"), self.v_file, cert_types() + [(_("Certificate request"), "*.csr")])

        box = ttk.LabelFrame(self, text=_("...or paste PEM text here"), padding=8)
        box.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        box.columnconfigure(0, weight=1)
        self.paste = tk.Text(box, height=5, font=("Consolas", 9), wrap="none")
        self.paste.grid(row=0, column=0, sticky="ew")

        btns = ttk.Frame(self)
        btns.grid(row=3, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(btns, text=_("Inspect"), command=self.inspect).pack(side="left")
        ttk.Button(btns, text=_("Paste from clipboard"), command=self.paste_clipboard).pack(side="left", padx=6)

        self.out = make_output_box(self, 4, _("Details"))
        self.rowconfigure(4, weight=1)

    def unsaved(self) -> str | None:
        return None

    def clear(self) -> None:
        self.paste.delete("1.0", "end")
        set_text(self.out, "")

    def paste_clipboard(self) -> None:
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return
        set_text(self.paste, text)

    def inspect(self) -> None:
        try:
            if self.v_file.get():
                data = Path(self.v_file.get()).read_bytes()
            else:
                text = self.paste.get("1.0", "end").strip()
                if not text:
                    messagebox.showerror(_("Error"), _("Select a file or paste PEM text."))
                    return
                data = text.encode("utf-8")
            set_text(self.out, csrgen.inspect_data(data))
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
        except OSError as exc:
            messagebox.showerror(_("Error"), _("Could not read file: {err}").format(err=exc))
