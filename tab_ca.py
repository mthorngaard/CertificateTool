"""Tab: a small local certificate authority (create a root CA, sign CSRs with it)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

import csrgen
from i18n import _
from ui_common import (
    CertForm, cert_types, confirm_unencrypted_key, csr_types, file_row, key_types, passwords_match,
    password_entry, safe_name, status_label, write_pem_set,
)


class LocalCaTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=6)
        self.app = app
        self.ca_result: csrgen.SelfSignedResult | None = None
        self.ca_saved = False
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        nb = ttk.Notebook(self)
        nb.grid(row=0, column=0, sticky="nsew")
        self.create_page = ttk.Frame(nb, padding=10)
        self.sign_page = ttk.Frame(nb, padding=10)
        nb.add(self.create_page, text=_("1. Create CA"))
        nb.add(self.sign_page, text=_("2. Sign a CSR"))
        self._build_create()
        self._build_sign()

    # ------------------------------------------------------------ state ----
    def unsaved(self) -> str | None:
        if self.ca_result is not None and not self.ca_saved:
            return _("the generated local CA certificate and its key")
        return None

    def clear(self) -> None:
        self.ca_result = None
        self.ca_saved = False
        for v in (self.v_pw, self.v_pw2, self.v_sign_pw):
            v.set("")
        self.btn_save_ca.config(state="disabled")
        self.status_create.set("")
        self.status_sign.set("")
        self.form.clear_sensitive()

    # ----------------------------------------------------------- create ----
    def _build_create(self) -> None:
        f = self.create_page
        f.columnconfigure(0, weight=1)
        ttk.Label(
            f,
            text=_(
                "A local CA lets you trust ONE root certificate on your clients and then sign as many\n"
                "server certificates as you like. Keep the CA key safe and protect it with a password."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.form = CertForm(f, show_san=False, dn_title=_("CA name (Common name e.g. \"My Company Root CA\")"))
        self.form.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.v_days = tk.StringVar(value="3650")
        self.v_pw = tk.StringVar()
        self.v_pw2 = tk.StringVar()
        opts = ttk.LabelFrame(f, text=_("Validity and CA key password"), padding=8)
        opts.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(opts, text=_("Valid for (days):")).grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=1, to=csrgen.MAX_VALIDITY_DAYS, textvariable=self.v_days, width=8).grid(
            row=0, column=1, sticky="w", padx=6
        )
        ttk.Label(opts, text=_("Password:")).grid(row=1, column=0, sticky="w", pady=(6, 0))
        password_entry(opts, self.v_pw).grid(row=1, column=1, padx=6, pady=(6, 0))
        ttk.Label(opts, text=_("Repeat:")).grid(row=1, column=2, padx=(12, 0), pady=(6, 0))
        password_entry(opts, self.v_pw2).grid(row=1, column=3, padx=6, pady=(6, 0))

        btns = ttk.Frame(f)
        btns.grid(row=3, column=0, columnspan=2, sticky="w", pady=10)
        self.btn_create = ttk.Button(btns, text=_("Create CA..."), command=self.create_ca)
        self.btn_create.pack(side="left")
        self.btn_save_ca = ttk.Button(
            btns, text=_("Save CA certificate + key..."), command=self.save_ca, state="disabled"
        )
        self.btn_save_ca.pack(side="left", padx=6)
        self.status_create = tk.StringVar()
        status_label(f, self.status_create, 4)

    def create_ca(self) -> None:
        if self.ca_result is not None and not self.ca_saved:
            if not messagebox.askyesno(
                _("Not saved"),
                _("The previous CA certificate and key have not been saved and will be lost.")
                + "\n\n" + _("Continue?"),
            ):
                return
        if not passwords_match(self.v_pw.get(), self.v_pw2.get()):
            return
        if not self.v_pw.get() and not confirm_unencrypted_key():
            return
        try:
            days = int(self.v_days.get())
        except ValueError:
            messagebox.showerror(_("Error"), _("Validity must be a whole number of days."))
            return
        req = self.form.get_request()
        try:
            csrgen.validate(req)
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        self.app.run_async(
            lambda: csrgen.generate_ca(req, days), self._created, [self.btn_create],
            (self.status_create, _("Generating CA key and certificate...")),
        )

    def _created(self, result: csrgen.SelfSignedResult) -> None:
        self.ca_result = result
        self.ca_saved = False
        self.form.remember()
        self.btn_save_ca.config(state="normal")
        self.status_create.set(
            _("Subject: {subject}").format(subject=result.subject) + "\n"
            + _("Valid until: {date}.").format(date=f"{result.not_after:%Y-%m-%d}")
        )
        self.save_ca()

    def save_ca(self) -> None:
        if not self.ca_result:
            return
        files = csrgen.build_pem_files(
            self.ca_result.cert_pem.encode("ascii"),
            csrgen.private_key_to_pem(self.ca_result.private_key), "", None, self.v_pw.get(),
        )
        msg = write_pem_set(files, safe_name(self.form.v_cn.get()))
        if msg:
            self.ca_saved = True
            self.v_pw.set("")
            self.v_pw2.set("")
            self.status_create.set(
                msg + "\n" + _(
                    "Install the .crt as a trusted root certificate on the clients. "
                    "Then use the \"Sign a CSR\" page to issue server certificates."
                )
            )

    # ------------------------------------------------------------- sign ----
    def _build_sign(self) -> None:
        f = self.sign_page
        f.columnconfigure(1, weight=1)
        ttk.Label(
            f,
            text=_(
                "Issue a TLS server certificate from a CSR (made on the \"Create CSR\" tab or by another system)\n"
                "using your local CA. The result is valid for the CSR's subject and SANs."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.v_csr = tk.StringVar()
        self.v_ca_cert = tk.StringVar()
        self.v_ca_key = tk.StringVar()
        self.v_sign_pw = tk.StringVar()
        self.v_sign_days = tk.StringVar(value=str(csrgen.RECOMMENDED_MAX_DAYS))

        file_row(f, 1, _("Certificate request (.csr):"), self.v_csr, csr_types())
        file_row(f, 2, _("CA certificate:"), self.v_ca_cert, cert_types())
        file_row(f, 3, _("CA private key:"), self.v_ca_key, key_types())
        ttk.Label(f, text=_("CA key password:")).grid(row=4, column=0, sticky="w", pady=3)
        password_entry(f, self.v_sign_pw, 28).grid(row=4, column=1, sticky="w", padx=6)
        ttk.Label(f, text=_("Valid for (days):")).grid(row=5, column=0, sticky="w", pady=3)
        ttk.Spinbox(
            f, from_=1, to=csrgen.MAX_VALIDITY_DAYS, textvariable=self.v_sign_days, width=8
        ).grid(row=5, column=1, sticky="w", padx=6)

        ttk.Button(f, text=_("Sign CSR and save..."), command=self.sign).grid(
            row=6, column=0, sticky="w", pady=10
        )
        self.status_sign = tk.StringVar()
        status_label(f, self.status_sign, 7, 3)

    def sign(self) -> None:
        if not (self.v_csr.get() and self.v_ca_cert.get() and self.v_ca_key.get()):
            messagebox.showerror(_("Error"), _("Select the CSR, the CA certificate and the CA private key."))
            return
        try:
            days = int(self.v_sign_days.get())
        except ValueError:
            messagebox.showerror(_("Error"), _("Validity must be a whole number of days."))
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
        try:
            ca_cert = Path(self.v_ca_cert.get()).read_bytes()
            result = csrgen.sign_csr(
                Path(self.v_csr.get()).read_bytes(), ca_cert,
                Path(self.v_ca_key.get()).read_bytes(), self.v_sign_pw.get(), days,
            )
        except csrgen.CsrError as exc:
            messagebox.showerror(_("Error"), str(exc))
            return
        except OSError as exc:
            messagebox.showerror(_("Error"), _("Could not read file: {err}").format(err=exc))
            return
        leaf_pem = result.cert_pem.encode("ascii")
        ca_pem = csrgen.certificates_to_pem(ca_cert)
        files = {"crt": leaf_pem, "chain": ca_pem, "fullchain": leaf_pem + ca_pem}
        csr_stem = Path(self.v_csr.get()).stem
        msg = write_pem_set(files, csr_stem, _("Save certificate (choose folder and base name)"))
        if msg:
            note = _("Valid until: {date}.").format(date=f"{result.not_after:%Y-%m-%d}")
            if result.clamped:
                note += " " + _("(shortened to the CA certificate's own expiry)")
            self.status_sign.set(
                msg + "\n" + note + "\n"
                + _("Combine the .crt with the private key of the CSR on the \"Export\" tab to make a PFX.")
            )
            self.v_sign_pw.set("")
