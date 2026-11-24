"""Tab: self-signed TLS server certificate."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import (
    CertForm, confirm_unencrypted_key, copy_to_clipboard, make_output_box, passwords_match,
    password_entry, safe_name, save_file_dialog, set_text, status_label, write_pem_set,
)


class SelfSignedTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.result: csrgen.SelfSignedResult | None = None
        self.saved = False
        self.columnconfigure(0, weight=1)

        self.form = CertForm(self)
        self.form.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.v_days = tk.StringVar(value="365")
        self.v_pw = tk.StringVar()
        self.v_pw2 = tk.StringVar()
        self.v_legacy = tk.BooleanVar(value=False)

        opts = ttk.LabelFrame(self, text=_("Validity and output passwords"), padding=8)
        opts.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(opts, text=_("Valid for (days):")).grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=1, to=csrgen.MAX_VALIDITY_DAYS, textvariable=self.v_days, width=8).grid(
            row=0, column=1, sticky="w", padx=6
        )
        ttk.Label(
            opts,
            text=_("Browsers/OS may reject more than {n} days.").format(n=csrgen.RECOMMENDED_MAX_DAYS),
            foreground="gray",
        ).grid(row=0, column=2, columnspan=2, sticky="w")
        ttk.Label(opts, text=_("Password:")).grid(row=1, column=0, sticky="w", pady=(6, 0))
        password_entry(opts, self.v_pw).grid(row=1, column=1, padx=6, pady=(6, 0))
        ttk.Label(opts, text=_("Repeat:")).grid(row=1, column=2, padx=(12, 0), pady=(6, 0))
        password_entry(opts, self.v_pw2).grid(row=1, column=3, padx=6, pady=(6, 0))
        ttk.Label(
            opts,
            text=_("Optional for CRT + KEY (empty = unencrypted key). Required for PFX."),
            foreground="gray",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(2, 0))
        ttk.Checkbutton(
            opts,
            text=_("PFX: compatible with older Windows (Server 2016 and earlier; 3DES/SHA1)"),
            variable=self.v_legacy,
        ).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        btns = ttk.Frame(self)
        btns.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        self.btn_generate = ttk.Button(btns, text=_("Generate certificate"), command=self.generate)
        self.btn_generate.pack(side="left")
        self.out_buttons = []
        for text, cmd in [
            (_("Copy certificate"), self.copy),
            (_("Save CRT + KEY..."), self.save_pem),
            (_("Save PFX..."), self.save_pfx),
        ]:
            b = ttk.Button(btns, text=text, command=cmd, state="disabled")
            b.pack(side="left", padx=(6, 0))
            self.out_buttons.append(b)

        self.out = make_output_box(self, 3, _("Certificate (PEM)"))
        self.status = tk.StringVar()
        status_label(self, self.status, 4)

    # ------------------------------------------------------------ state ----
    def unsaved(self) -> str | None:
        if self.result is not None and not self.saved:
            return _("the generated self-signed certificate and its key")
        return None

    def clear(self) -> None:
        self.result = None
        self.saved = False
        self.v_pw.set("")
        self.v_pw2.set("")
        for b in self.out_buttons:
            b.config(state="disabled")
        set_text(self.out, "")
        self.status.set("")
        self.form.clear_sensitive()

    # --------------------------------------------------------- actions ----
    def _validity_days(self) -> int | None:
        try:
            return int(self.v_days.get())
        except ValueError:
            messagebox.showerror(_("Error"), _("Validity must be a whole number of days."))
            return None

    def generate(self) -> None:
        if self.result is not None and not self.saved:
            if not messagebox.askyesno(
                _("Not saved"),
                _("The previous certificate and key have not been saved and will be lost.")
                + "\n\n" + _("Continue?"),
            ):
                return
        days = self._validity_days()
        if days is None:
            return
        if days > csrgen.RECOMMENDED_MAX_DAYS and not messagebox.askyesno(
            _("Long validity"),
            _("A validity of {days} days is longer than {n} days. Some browsers and operating systems "
              "(for example Apple's) reject such certificates.").format(
                days=days, n=csrgen.RECOMMENDED_MAX_DAYS)
            + "\n\n" + _("Continue?"),
            icon="warning",
        ):
            return
        req = self.form.get_request()
        try:
            csrgen.validate(req)
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        self.app.run_async(
            lambda: csrgen.generate_self_signed(req, days), self._generated, [self.btn_generate],
            (self.status, _("Generating key and certificate...")),
        )

    def _generated(self, result: csrgen.SelfSignedResult) -> None:
        self.result = result
        self.saved = False
        self.form.remember()
        set_text(self.out, result.cert_pem)
        for b in self.out_buttons:
            b.config(state="normal")
        san_txt = ", ".join(result.sans) or _("none")
        self.status.set(
            _("Subject: {subject}").format(subject=result.subject) + "\n"
            + _("SAN: {sans}").format(sans=san_txt) + "\n"
            + _("Valid until: {date}.").format(date=f"{result.not_after:%Y-%m-%d}") + " "
            + _("Save the certificate together with its private key.")
        )

    def copy(self) -> None:
        if not self.result:
            return
        copy_to_clipboard(self, self.result.cert_pem)
        self.status.set(_("Certificate copied to the clipboard."))

    def _passwords_ok(self) -> bool:
        return passwords_match(self.v_pw.get(), self.v_pw2.get())

    def _after_save(self, message: str) -> None:
        self.saved = True
        self.v_pw.set("")
        self.v_pw2.set("")
        self.status.set(message)

    def save_pem(self) -> None:
        if not self.result or not self._passwords_ok():
            return
        pw = self.v_pw.get()
        if not pw and not confirm_unencrypted_key():
            return
        files = csrgen.build_pem_files(
            self.result.cert_pem.encode("ascii"), csrgen.private_key_to_pem(self.result.private_key),
            "", None, pw,
        )
        msg = write_pem_set(files, safe_name(self.form.v_cn.get()))
        if msg:
            self._after_save(msg)

    def save_pfx(self) -> None:
        if not self.result or not self._passwords_ok():
            return
        if not self.v_pw.get():
            messagebox.showerror(
                _("Error"), _("Enter a password for the PFX file (IIS requires one on import).")
            )
            return
        pfx = csrgen.build_pfx(
            self.result.cert_pem.encode("ascii"), csrgen.private_key_to_pem(self.result.private_key),
            "", None, self.v_pw.get(), self.form.v_cn.get().strip(), self.v_legacy.get(),
        )
        path = save_file_dialog(
            _("Save PFX"), ".pfx", safe_name(self.form.v_cn.get()),
            [("PFX", "*.pfx"), (_("All files"), "*.*")],
        )
        if path:
            csrgen.write_private_file(path, pfx)
            self._after_save(_("PFX saved: {path}").format(path=path))
