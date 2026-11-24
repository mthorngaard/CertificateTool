"""Tab: create a certificate signing request (CSR)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import (
    CertForm, confirm_unencrypted_key, copy_to_clipboard, file_row, key_types,
    make_output_box, passwords_match, password_entry, safe_name, save_file_dialog, set_text,
    status_label,
)


class CsrTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.result: csrgen.CsrResult | None = None
        self.key_saved = False
        self.columnconfigure(0, weight=1)

        self.form = CertForm(self)
        self.form.grid(row=0, column=0, columnspan=2, sticky="ew")

        # ---- reuse an existing key (renewal)
        self.v_reuse = tk.BooleanVar(value=False)
        self.v_exkey = tk.StringVar()
        self.v_exkey_pw = tk.StringVar()
        reuse = ttk.LabelFrame(self, text=_("Renewal"), padding=8)
        reuse.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        reuse.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            reuse, text=_("Use an existing private key instead of generating a new one"),
            variable=self.v_reuse, command=self._toggle_reuse,
        ).grid(row=0, column=0, columnspan=3, sticky="w")
        file_row(reuse, 1, _("Private key (.key/.pem):"), self.v_exkey, key_types())
        ttk.Label(reuse, text=_("Key password:")).grid(row=2, column=0, sticky="w", pady=3)
        password_entry(reuse, self.v_exkey_pw).grid(row=2, column=1, sticky="w", padx=6)
        self.reuse_children = [w for w in reuse.winfo_children() if w.grid_info().get("row", 0) >= 1]
        self._toggle_reuse()

        # ---- save password
        self.v_keypw = tk.StringVar()
        self.v_keypw2 = tk.StringVar()
        key = ttk.LabelFrame(self, text=_("Protect private key with a password (optional)"), padding=8)
        key.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(key, text=_("Password:")).grid(row=0, column=0, sticky="w")
        password_entry(key, self.v_keypw).grid(row=0, column=1, padx=6)
        ttk.Label(key, text=_("Repeat:")).grid(row=0, column=2, padx=(12, 0))
        password_entry(key, self.v_keypw2).grid(row=0, column=3, padx=6)

        btns = ttk.Frame(self)
        btns.grid(row=5, column=0, columnspan=2, sticky="ew", pady=10)
        self.btn_generate = ttk.Button(btns, text=_("Generate CSR"), command=self.generate)
        self.btn_generate.pack(side="left")
        self.btn_copy = ttk.Button(btns, text=_("Copy CSR"), command=self.copy, state="disabled")
        self.btn_copy.pack(side="left", padx=6)
        self.btn_save_csr = ttk.Button(btns, text=_("Save CSR..."), command=self.save_csr, state="disabled")
        self.btn_save_csr.pack(side="left")
        self.btn_save_key = ttk.Button(
            btns, text=_("Save private key..."), command=self.save_key, state="disabled"
        )
        self.btn_save_key.pack(side="left", padx=6)

        self.out = make_output_box(self, 6, _("CSR (paste into the CA's admin portal)"))
        self.status = tk.StringVar()
        status_label(self, self.status, 7)
        self.form.cn_entry.focus_set()

    # ------------------------------------------------------------ state ----
    def unsaved(self) -> str | None:
        if self.result is not None and not self.key_saved:
            return _("the private key for the generated CSR")
        return None

    def clear(self) -> None:
        self.result = None
        self.key_saved = False
        for v in (self.v_keypw, self.v_keypw2, self.v_exkey_pw):
            v.set("")
        for b in (self.btn_copy, self.btn_save_csr, self.btn_save_key):
            b.config(state="disabled")
        set_text(self.out, "")
        self.status.set("")
        self.form.clear_sensitive()

    def _toggle_reuse(self) -> None:
        for w in self.reuse_children:
            if self.v_reuse.get():
                w.grid()
            else:
                w.grid_remove()
        self.form.set_crypto_enabled(not self.v_reuse.get())

    # --------------------------------------------------------- actions ----
    def generate(self) -> None:
        if self.result is not None and not self.key_saved:
            if not messagebox.askyesno(
                _("Private key not saved"),
                _("The previous private key has not been saved and will be lost if you generate a new one.")
                + "\n\n" + _("Continue?"),
            ):
                return
        if not passwords_match(self.v_keypw.get(), self.v_keypw2.get()):
            return
        existing = None
        if self.v_reuse.get():
            if not self.v_exkey.get():
                messagebox.showerror(_("Error"), _("Select the existing private key."))
                return
            try:
                existing = csrgen.load_key(Path(self.v_exkey.get()).read_bytes(), self.v_exkey_pw.get())
            except csrgen.CsrError as exc:
                messagebox.showerror(_("Error"), str(exc))
                return
            except OSError as exc:
                messagebox.showerror(_("Error"), _("Could not read file: {err}").format(err=exc))
                return
        req = self.form.get_request(existing)
        try:
            csrgen.validate(req)
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        self.app.run_async(
            lambda: csrgen.generate_csr(req), self._generated, [self.btn_generate],
            (self.status, _("Generating key and CSR...")),
        )

    def _generated(self, result: csrgen.CsrResult) -> None:
        self.result = result
        self.key_saved = result.reused_key
        self.form.remember()
        set_text(self.out, result.csr_pem)
        for b in (self.btn_copy, self.btn_save_csr, self.btn_save_key):
            b.config(state="normal")
        san_txt = ", ".join(result.sans) or _("none")
        if result.reused_key:
            tail = _("The existing private key was reused - keep using that key file with the issued certificate.")
        else:
            tail = _("Remember to save the private key - the certificate is useless without it.")
        self.status.set(
            _("Subject: {subject}").format(subject=result.subject) + "\n"
            + _("SAN: {sans}").format(sans=san_txt) + "\n" + tail
        )

    def copy(self) -> None:
        if not self.result:
            return
        copy_to_clipboard(self, self.result.csr_pem)
        self.status.set(_("CSR copied to the clipboard."))

    def save_csr(self) -> None:
        if not self.result:
            return
        path = save_file_dialog(
            _("Save CSR"), ".csr", safe_name(self.form.v_cn.get()),
            [(_("Certificate request"), "*.csr"), (_("Text file"), "*.txt"), (_("All files"), "*.*")],
        )
        if path:
            csrgen.write_text_file(path, self.result.csr_pem)
            self.status.set(_("CSR saved: {path}").format(path=path))

    def save_key(self) -> None:
        if not self.result:
            return
        pw, pw2 = self.v_keypw.get(), self.v_keypw2.get()
        if not passwords_match(pw, pw2):
            return
        if not pw and not confirm_unencrypted_key():
            return
        path = save_file_dialog(
            _("Save private key"), ".key", safe_name(self.form.v_cn.get()),
            [(_("Private key (PEM)"), "*.key"), ("PEM", "*.pem"), (_("All files"), "*.*")],
        )
        if path:
            csrgen.write_private_file(path, csrgen.private_key_to_pem(self.result.private_key, pw))
            self.key_saved = True
            self.v_keypw.set("")
            self.v_keypw2.set("")
            self.status.set(_("Private key saved: {path}").format(path=path))
