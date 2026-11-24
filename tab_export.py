"""Tab: combine an issued certificate + private key (+ chain) into PFX or CRT+KEY files."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import (
    cert_types, confirm_unencrypted_key, confirm_warnings, file_row, key_types, passwords_match,
    password_entry, safe_name, save_file_dialog, status_label, write_pem_set,
)


class ExportTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        f = self
        f.columnconfigure(1, weight=1)
        ttk.Label(
            f,
            text=_(
                "Once the CA has issued the certificate, combine it with the private key into a .pfx file\n"
                "(IIS: Server Certificates > Import) or into the PEM files .crt + .key (nginx, Apache, etc.)."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.v_cert = tk.StringVar()
        self.v_key = tk.StringVar()
        self.v_keypw = tk.StringVar()
        self.v_chain = tk.StringVar()
        self.v_name = tk.StringVar()
        self.v_pw = tk.StringVar()
        self.v_pw2 = tk.StringVar()
        self.v_legacy = tk.BooleanVar(value=False)
        self.v_aia = tk.BooleanVar(value=False)
        self.v_fmt = tk.StringVar(value="pfx")

        file_row(f, 1, _("Certificate (.cer/.crt/.pem/.p7b):"), self.v_cert, cert_types())
        file_row(f, 2, _("Private key (.key/.pem):"), self.v_key, key_types())
        ttk.Label(f, text=_("Private key password:")).grid(row=3, column=0, sticky="w", pady=3)
        password_entry(f, self.v_keypw, 28).grid(row=3, column=1, sticky="w", padx=6)
        file_row(f, 4, _("Intermediate/root certs (optional):"), self.v_chain, cert_types())
        ttk.Checkbutton(
            f,
            text=_("Download missing intermediate certificates from the CA (uses the network)"),
            variable=self.v_aia,
        ).grid(row=5, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Label(f, text=_("Friendly name (optional):")).grid(row=6, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.v_name).grid(row=6, column=1, sticky="ew", padx=6)

        ttk.Separator(f).grid(row=7, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(f, text=_("Output format:")).grid(row=8, column=0, sticky="w", pady=3)
        fmt = ttk.Frame(f)
        fmt.grid(row=8, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Radiobutton(
            fmt, text=_("PFX (IIS/Windows)"), variable=self.v_fmt, value="pfx", command=self._update_fmt
        ).pack(side="left")
        ttk.Radiobutton(
            fmt, text=_("CRT + KEY (PEM: nginx, Apache, etc.)"), variable=self.v_fmt, value="pem",
            command=self._update_fmt,
        ).pack(side="left", padx=12)

        self.pw_label = ttk.Label(f, text=_("PFX password:"))
        self.pw_label.grid(row=9, column=0, sticky="w", pady=3)
        password_entry(f, self.v_pw, 28).grid(row=9, column=1, sticky="w", padx=6)
        ttk.Label(f, text=_("Repeat:")).grid(row=10, column=0, sticky="w", pady=3)
        password_entry(f, self.v_pw2, 28).grid(row=10, column=1, sticky="w", padx=6)
        self.legacy_cb = ttk.Checkbutton(
            f,
            text=_("Compatible with older Windows (Server 2016 and earlier; 3DES/SHA1)"),
            variable=self.v_legacy,
        )
        self.legacy_cb.grid(row=11, column=0, columnspan=3, sticky="w", pady=4)
        self.pem_hint = ttk.Label(
            f,
            text=_(
                "Creates: <name>.crt (certificate only), <name>.key (private key) and - if a chain is given -\n"
                "<name>-chain.crt and <name>-fullchain.crt (certificate + chain). Leave the password empty for\n"
                "an unencrypted key, which most web servers require."
            ),
            foreground="gray",
            justify="left",
        )
        self.pem_hint.grid(row=12, column=0, columnspan=3, sticky="w")
        self.pem_hint.grid_remove()

        self.btn = ttk.Button(f, text=_("Create PFX..."), command=self.make_output)
        self.btn.grid(row=13, column=0, sticky="w", pady=10)
        self.status = tk.StringVar()
        status_label(f, self.status, 14, 3)

    def unsaved(self) -> str | None:
        return None

    def clear(self) -> None:
        for v in (self.v_keypw, self.v_pw, self.v_pw2):
            v.set("")
        self.status.set("")

    def _update_fmt(self) -> None:
        if self.v_fmt.get() == "pfx":
            self.pw_label.config(text=_("PFX password:"))
            self.btn.config(text=_("Create PFX..."))
            self.legacy_cb.grid()
            self.pem_hint.grid_remove()
        else:
            self.pw_label.config(text=_("Key password (optional):"))
            self.btn.config(text=_("Create CRT + KEY..."))
            self.legacy_cb.grid_remove()
            self.pem_hint.grid()

    def make_output(self) -> None:
        if not self.v_cert.get() or not self.v_key.get():
            messagebox.showerror(_("Error"), _("Select both a certificate and a private key."))
            return
        pem = self.v_fmt.get() == "pem"
        if not pem and not self.v_pw.get():
            messagebox.showerror(
                _("Error"), _("Enter a password for the PFX file (IIS requires one on import).")
            )
            return
        if not passwords_match(self.v_pw.get(), self.v_pw2.get()):
            return
        if pem and not self.v_pw.get() and not confirm_unencrypted_key():
            return
        try:
            cert = Path(self.v_cert.get()).read_bytes()
            key = Path(self.v_key.get()).read_bytes()
            chain = Path(self.v_chain.get()).read_bytes() if self.v_chain.get() else None
            if self.v_aia.get():
                self.app.config(cursor="watch")
                self.app.update_idletasks()
            try:
                bundle = csrgen.prepare_export(cert, key, self.v_keypw.get(), chain, self.v_aia.get())
            finally:
                self.app.config(cursor="")
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        except OSError as exc:
            messagebox.showerror(_("Error"), _("Could not read file: {err}").format(err=exc))
            return
        if not confirm_warnings(bundle.warnings, bundle.notes):
            return

        stem = Path(self.v_cert.get()).stem
        notes = ("\n" + "\n".join(bundle.notes)) if bundle.notes else ""
        if pem:
            msg = write_pem_set(csrgen.pem_files(bundle, self.v_pw.get()), stem)
            if msg:
                self.status.set(msg + notes)
                self._clear_passwords()
            return
        pfx = csrgen.pfx_bytes(bundle, self.v_pw.get(), self.v_name.get(), self.v_legacy.get())
        path = save_file_dialog(
            _("Save PFX"), ".pfx", safe_name(stem), [("PFX", "*.pfx"), (_("All files"), "*.*")]
        )
        if path:
            csrgen.write_private_file(path, pfx)
            self.status.set(_("PFX saved: {path}").format(path=path) + notes)
            self._clear_passwords()

    def _clear_passwords(self) -> None:
        for v in (self.v_keypw, self.v_pw, self.v_pw2):
            v.set("")
