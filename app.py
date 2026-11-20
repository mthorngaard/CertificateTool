"""CSR / self-signed certificate generator with a GUI.

Uses the same fields as IIS' "Create Certificate Request" wizard.
"""

from __future__ import annotations

import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import csrgen

COUNTRIES = [
    "DK", "SE", "NO", "FI", "IS", "DE", "NL", "BE", "FR", "GB", "IE", "ES", "IT",
    "PL", "AT", "CH", "US", "CA", "GL", "FO",
]

CERT_TYPES = [("Certificates", "*.cer *.crt *.pem *.p7b *.p7c"), ("All files", "*.*")]


def safe_name(common_name: str) -> str:
    name = common_name.strip().replace("*", "wildcard")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "certificate"


class CertForm(ttk.Frame):
    """DN fields + cryptography + SAN. Shared by the CSR and self-signed tabs."""

    def __init__(self, master) -> None:
        super().__init__(master)
        self.columnconfigure(0, weight=1)

        self.v_cn = tk.StringVar()
        self.v_o = tk.StringVar()
        self.v_ou = tk.StringVar()
        self.v_l = tk.StringVar()
        self.v_st = tk.StringVar()
        self.v_c = tk.StringVar(value="DK")
        self.v_alg = tk.StringVar(value="RSA")
        self.v_size = tk.StringVar(value="2048")
        self.v_hash = tk.StringVar(value="SHA-256")
        self.v_cn_san = tk.BooleanVar(value=True)

        grp = ttk.LabelFrame(self, text="Distinguished Name (same as IIS)", padding=8)
        grp.grid(row=0, column=0, sticky="ew")
        grp.columnconfigure(1, weight=1)

        rows = [
            ("Common name:", self.v_cn, "e.g. www.example.com or *.example.com"),
            ("Organization:", self.v_o, "Full legal name of the company"),
            ("Organizational unit:", self.v_ou, "e.g. IT"),
            ("City/locality:", self.v_l, ""),
            ("State/province:", self.v_st, "Spell it out in full, no abbreviations"),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(grp, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ent = ttk.Entry(grp, textvariable=var)
            ent.grid(row=i, column=1, sticky="ew", padx=6, pady=2)
            ttk.Label(grp, text=hint, foreground="gray").grid(row=i, column=2, sticky="w")
            if i == 0:
                self.cn_entry = ent
        r = len(rows)
        ttk.Label(grp, text="Country/region:").grid(row=r, column=0, sticky="w", pady=2)
        ttk.Combobox(grp, textvariable=self.v_c, values=COUNTRIES, width=6).grid(
            row=r, column=1, sticky="w", padx=6, pady=2
        )
        ttk.Label(grp, text="2-letter country code", foreground="gray").grid(row=r, column=2, sticky="w")

        crypto = ttk.LabelFrame(self, text="Cryptography", padding=8)
        crypto.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(crypto, text="Key type:").grid(row=0, column=0, sticky="w")
        alg = ttk.Combobox(
            crypto, textvariable=self.v_alg, values=csrgen.KEY_ALGORITHMS, state="readonly", width=8
        )
        alg.grid(row=0, column=1, padx=6)
        alg.bind("<<ComboboxSelected>>", lambda _e: self._update_sizes())
        self.size_label = ttk.Label(crypto, text="Bit length:")
        self.size_label.grid(row=0, column=2, padx=(12, 0))
        self.size_box = ttk.Combobox(
            crypto, textvariable=self.v_size, values=csrgen.RSA_SIZES, state="readonly", width=8
        )
        self.size_box.grid(row=0, column=3, padx=6)
        ttk.Label(crypto, text="Hash:").grid(row=0, column=4, padx=(12, 0))
        ttk.Combobox(
            crypto, textvariable=self.v_hash, values=list(csrgen.HASHES), state="readonly", width=9
        ).grid(row=0, column=5, padx=6)

        san = ttk.LabelFrame(self, text="Subject Alternative Names (optional - one per line)", padding=8)
        san.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        san.columnconfigure(0, weight=1)
        self.san_text = tk.Text(san, height=3, width=40, wrap="word")
        self.san_text.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            san, text="Include Common name as a SAN (recommended)", variable=self.v_cn_san
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

    def _update_sizes(self) -> None:
        if self.v_alg.get() == "RSA":
            self.size_label.config(text="Bit length:")
            self.size_box.config(values=csrgen.RSA_SIZES)
            self.v_size.set("2048")
        else:
            self.size_label.config(text="Curve:")
            self.size_box.config(values=list(csrgen.EC_CURVES))
            self.v_size.set("P-256")

    def get_request(self) -> csrgen.CsrRequest:
        return csrgen.CsrRequest(
            common_name=self.v_cn.get(),
            organization=self.v_o.get(),
            organizational_unit=self.v_ou.get(),
            locality=self.v_l.get(),
            state=self.v_st.get(),
            country=self.v_c.get(),
            key_algorithm=self.v_alg.get(),
            key_size=self.v_size.get(),
            hash_name=self.v_hash.get(),
            san_entries=csrgen.parse_san_text(self.san_text.get("1.0", "end")),
            include_cn_in_san=self.v_cn_san.get(),
        )


def make_output_box(parent, row: int, title: str) -> tk.Text:
    out = ttk.LabelFrame(parent, text=title, padding=8)
    out.grid(row=row, column=0, columnspan=2, sticky="nsew")
    parent.rowconfigure(row, weight=1)
    out.columnconfigure(0, weight=1)
    out.rowconfigure(0, weight=1)
    box = tk.Text(out, height=8, font=("Consolas", 9), wrap="none")
    box.grid(row=0, column=0, sticky="nsew")
    sb = ttk.Scrollbar(out, command=box.yview)
    sb.grid(row=0, column=1, sticky="ns")
    box.configure(yscrollcommand=sb.set)
    return box


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Certificate Tool")
        self.minsize(780, 720)
        self.result: csrgen.CsrResult | None = None
        self.key_saved = False
        self.ss_result: csrgen.SelfSignedResult | None = None
        self.ss_saved = False

        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.csr_tab = ttk.Frame(nb, padding=10)
        self.ss_tab = ttk.Frame(nb, padding=10)
        self.pfx_tab = ttk.Frame(nb, padding=10)
        nb.add(self.csr_tab, text="Create CSR")
        nb.add(self.ss_tab, text="Self-signed certificate")
        nb.add(self.pfx_tab, text="Export certificate (PFX / CRT+KEY)")

        self._build_csr_tab()
        self._build_ss_tab()
        self._build_pfx_tab()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------ CSR ----
    def _build_csr_tab(self) -> None:
        f = self.csr_tab
        f.columnconfigure(0, weight=1)
        self.csr_form = CertForm(f)
        self.csr_form.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.v_keypw = tk.StringVar()
        self.v_keypw2 = tk.StringVar()
        key = ttk.LabelFrame(f, text="Protect private key with a password (optional)", padding=8)
        key.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(key, text="Password:").grid(row=0, column=0, sticky="w")
        ttk.Entry(key, textvariable=self.v_keypw, show="*", width=24).grid(row=0, column=1, padx=6)
        ttk.Label(key, text="Repeat:").grid(row=0, column=2, padx=(12, 0))
        ttk.Entry(key, textvariable=self.v_keypw2, show="*", width=24).grid(row=0, column=3, padx=6)

        btns = ttk.Frame(f)
        btns.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Button(btns, text="Generate CSR", command=self._generate).pack(side="left")
        self.btn_copy = ttk.Button(btns, text="Copy CSR", command=self._copy, state="disabled")
        self.btn_copy.pack(side="left", padx=6)
        self.btn_save_csr = ttk.Button(btns, text="Save CSR...", command=self._save_csr, state="disabled")
        self.btn_save_csr.pack(side="left")
        self.btn_save_key = ttk.Button(
            btns, text="Save private key...", command=self._save_key, state="disabled"
        )
        self.btn_save_key.pack(side="left", padx=6)

        self.csr_out = make_output_box(f, 5, "CSR (paste into the CA's admin portal)")

        self.status = tk.StringVar()
        ttk.Label(f, textvariable=self.status, foreground="#555", wraplength=720).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )
        self.csr_form.cn_entry.focus_set()

    def _generate(self) -> None:
        if self.result is not None and not self.key_saved:
            if not messagebox.askyesno(
                "Private key not saved",
                "The previous private key has not been saved and will be lost if you generate a new one.\n\nContinue?",
            ):
                return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.result = csrgen.generate_csr(self.csr_form.get_request())
        except csrgen.CsrError as exc:
            messagebox.showerror("Error", str(exc))
            return
        finally:
            self.config(cursor="")
        self.key_saved = False
        self.csr_out.delete("1.0", "end")
        self.csr_out.insert("1.0", self.result.csr_pem)
        for b in (self.btn_copy, self.btn_save_csr, self.btn_save_key):
            b.config(state="normal")
        san_txt = ", ".join(self.result.sans) or "none"
        self.status.set(
            f"Subject: {self.result.subject}\nSAN: {san_txt}\n"
            "Remember to save the private key - the certificate is useless without it."
        )

    def _copy(self) -> None:
        if not self.result:
            return
        self.clipboard_clear()
        self.clipboard_append(self.result.csr_pem)
        self.update()
        self.status.set("CSR copied to the clipboard.")

    def _save_csr(self) -> None:
        if not self.result:
            return
        path = filedialog.asksaveasfilename(
            title="Save CSR",
            defaultextension=".csr",
            initialfile=safe_name(self.csr_form.v_cn.get()) + ".csr",
            filetypes=[("Certificate request", "*.csr"), ("Text file", "*.txt"), ("All files", "*.*")],
        )
        if path:
            Path(path).write_text(self.result.csr_pem, encoding="ascii", newline="\n")
            self.status.set(f"CSR saved: {path}")

    def _save_key(self) -> None:
        if not self.result:
            return
        pw, pw2 = self.v_keypw.get(), self.v_keypw2.get()
        if pw != pw2:
            messagebox.showerror("Error", "The passwords do not match.")
            return
        if not pw and not messagebox.askyesno(
            "No password",
            "The private key will be saved UNENCRYPTED. Anyone with access to the file can use it.\n\nContinue?",
        ):
            return
        path = filedialog.asksaveasfilename(
            title="Save private key",
            defaultextension=".key",
            initialfile=safe_name(self.csr_form.v_cn.get()) + ".key",
            filetypes=[("Private key (PEM)", "*.key"), ("PEM", "*.pem"), ("All files", "*.*")],
        )
        if path:
            Path(path).write_bytes(csrgen.private_key_to_pem(self.result.private_key, pw))
            self.key_saved = True
            self.status.set(f"Private key saved: {path}")

    # ---------------------------------------------------- Self-signed ----
    def _build_ss_tab(self) -> None:
        f = self.ss_tab
        f.columnconfigure(0, weight=1)
        self.ss_form = CertForm(f)
        self.ss_form.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.ss_days = tk.StringVar(value="365")
        self.ss_keypw = tk.StringVar()
        self.ss_pw2 = tk.StringVar()
        self.ss_legacy = tk.BooleanVar(value=False)

        opts = ttk.LabelFrame(f, text="Validity and output passwords", padding=8)
        opts.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(opts, text="Valid for (days):").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=1, to=csrgen.MAX_VALIDITY_DAYS, textvariable=self.ss_days, width=8).grid(
            row=0, column=1, sticky="w", padx=6
        )
        ttk.Label(opts, text="Password:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(opts, textvariable=self.ss_keypw, show="*", width=24).grid(
            row=1, column=1, padx=6, pady=(6, 0)
        )
        ttk.Label(opts, text="Repeat:").grid(row=1, column=2, padx=(12, 0), pady=(6, 0))
        ttk.Entry(opts, textvariable=self.ss_pw2, show="*", width=24).grid(
            row=1, column=3, padx=6, pady=(6, 0)
        )
        ttk.Label(
            opts,
            text="Optional for CRT + KEY (empty = unencrypted key). Required for PFX.",
            foreground="gray",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(2, 0))
        ttk.Checkbutton(
            opts,
            text="PFX: compatible with older Windows (Server 2016 and earlier; 3DES/SHA1)",
            variable=self.ss_legacy,
        ).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        btns = ttk.Frame(f)
        btns.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        ttk.Button(btns, text="Generate certificate", command=self._ss_generate).pack(side="left")
        self.ss_btns = []
        for text, cmd in [
            ("Copy certificate", self._ss_copy),
            ("Save CRT + KEY...", self._ss_save_pem),
            ("Save PFX...", self._ss_save_pfx),
        ]:
            b = ttk.Button(btns, text=text, command=cmd, state="disabled")
            b.pack(side="left", padx=(6, 0))
            self.ss_btns.append(b)

        self.ss_out = make_output_box(f, 3, "Certificate (PEM)")
        self.ss_status = tk.StringVar()
        ttk.Label(f, textvariable=self.ss_status, foreground="#555", wraplength=720).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

    def _ss_validity_days(self) -> int | None:
        try:
            return int(self.ss_days.get())
        except ValueError:
            messagebox.showerror("Error", "Validity must be a whole number of days.")
            return None

    def _ss_generate(self) -> None:
        if self.ss_result is not None and not self.ss_saved:
            if not messagebox.askyesno(
                "Not saved",
                "The previous certificate and key have not been saved and will be lost.\n\nContinue?",
            ):
                return
        days = self._ss_validity_days()
        if days is None:
            return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.ss_result = csrgen.generate_self_signed(self.ss_form.get_request(), days)
        except csrgen.CsrError as exc:
            messagebox.showerror("Error", str(exc))
            return
        finally:
            self.config(cursor="")
        self.ss_saved = False
        self.ss_out.delete("1.0", "end")
        self.ss_out.insert("1.0", self.ss_result.cert_pem)
        for b in self.ss_btns:
            b.config(state="normal")
        san_txt = ", ".join(self.ss_result.sans) or "none"
        self.ss_status.set(
            f"Subject: {self.ss_result.subject}\nSAN: {san_txt}\n"
            f"Valid until: {self.ss_result.not_after:%Y-%m-%d}. "
            "Save the certificate together with its private key."
        )

    def _ss_copy(self) -> None:
        if not self.ss_result:
            return
        self.clipboard_clear()
        self.clipboard_append(self.ss_result.cert_pem)
        self.update()
        self.ss_status.set("Certificate copied to the clipboard.")

    def _ss_passwords_ok(self) -> bool:
        if self.ss_keypw.get() != self.ss_pw2.get():
            messagebox.showerror("Error", "The passwords do not match.")
            return False
        return True

    def _ss_save_pem(self) -> None:
        if not self.ss_result or not self._ss_passwords_ok():
            return
        pw = self.ss_keypw.get()
        if not pw and not messagebox.askyesno(
            "No password",
            "The key file (.key) will be saved UNENCRYPTED. Anyone with access to the file can use it.\n\nContinue?",
        ):
            return
        files = csrgen.build_pem_files(
            self.ss_result.cert_pem.encode("ascii"),
            csrgen.private_key_to_pem(self.ss_result.private_key),
            "", None, pw,
        )
        msg = self._write_pem_set(files, safe_name(self.ss_form.v_cn.get()))
        if msg:
            self.ss_saved = True
            self.ss_status.set(msg)

    def _ss_save_pfx(self) -> None:
        if not self.ss_result or not self._ss_passwords_ok():
            return
        if not self.ss_keypw.get():
            messagebox.showerror("Error", "Enter a password for the PFX file (IIS requires one on import).")
            return
        pfx = csrgen.build_pfx(
            self.ss_result.cert_pem.encode("ascii"),
            csrgen.private_key_to_pem(self.ss_result.private_key),
            "", None, self.ss_keypw.get(), self.ss_form.v_cn.get().strip(), self.ss_legacy.get(),
        )
        path = filedialog.asksaveasfilename(
            title="Save PFX",
            defaultextension=".pfx",
            initialfile=safe_name(self.ss_form.v_cn.get()) + ".pfx",
            filetypes=[("PFX", "*.pfx"), ("All files", "*.*")],
        )
        if path:
            Path(path).write_bytes(pfx)
            self.ss_saved = True
            self.ss_status.set(f"PFX saved: {path}")

    # ------------------------------------------------------------ PFX ----
    def _build_pfx_tab(self) -> None:
        f = self.pfx_tab
        f.columnconfigure(1, weight=1)
        ttk.Label(
            f,
            text=(
                "Once the CA has issued the certificate, combine it with the private key into a .pfx file\n"
                "(IIS: Server Certificates > Import) or into the PEM files .crt + .key (nginx, Apache, etc.)."
            ),
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.p_cert = tk.StringVar()
        self.p_key = tk.StringVar()
        self.p_keypw = tk.StringVar()
        self.p_chain = tk.StringVar()
        self.p_name = tk.StringVar()
        self.p_pfxpw = tk.StringVar()
        self.p_pfxpw2 = tk.StringVar()
        self.p_legacy = tk.BooleanVar(value=False)
        self.p_fmt = tk.StringVar(value="pfx")

        def file_row(r: int, label: str, var: tk.StringVar, types) -> None:
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=var).grid(row=r, column=1, sticky="ew", padx=6)
            ttk.Button(
                f,
                text="Browse...",
                command=lambda: var.set(filedialog.askopenfilename(filetypes=types) or var.get()),
            ).grid(row=r, column=2)

        file_row(1, "Certificate (.cer/.crt/.pem/.p7b):", self.p_cert, CERT_TYPES)
        file_row(2, "Private key (.key/.pem):", self.p_key,
                 [("Private key", "*.key *.pem"), ("All files", "*.*")])
        ttk.Label(f, text="Private key password:").grid(row=3, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.p_keypw, show="*", width=28).grid(row=3, column=1, sticky="w", padx=6)
        file_row(4, "Intermediate/root certs (optional):", self.p_chain, CERT_TYPES)
        ttk.Label(f, text="Friendly name (optional):").grid(row=5, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.p_name).grid(row=5, column=1, sticky="ew", padx=6)

        ttk.Separator(f).grid(row=6, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(f, text="Output format:").grid(row=7, column=0, sticky="w", pady=3)
        fmt = ttk.Frame(f)
        fmt.grid(row=7, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Radiobutton(
            fmt, text="PFX (IIS/Windows)", variable=self.p_fmt, value="pfx", command=self._update_fmt
        ).pack(side="left")
        ttk.Radiobutton(
            fmt, text="CRT + KEY (PEM: nginx, Apache, etc.)", variable=self.p_fmt, value="pem",
            command=self._update_fmt,
        ).pack(side="left", padx=12)

        self.pw_label = ttk.Label(f, text="PFX password:")
        self.pw_label.grid(row=8, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.p_pfxpw, show="*", width=28).grid(row=8, column=1, sticky="w", padx=6)
        ttk.Label(f, text="Repeat:").grid(row=9, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.p_pfxpw2, show="*", width=28).grid(row=9, column=1, sticky="w", padx=6)
        self.legacy_cb = ttk.Checkbutton(
            f,
            text="Compatible with older Windows (Server 2016 and earlier; 3DES/SHA1)",
            variable=self.p_legacy,
        )
        self.legacy_cb.grid(row=10, column=0, columnspan=3, sticky="w", pady=4)
        self.pem_hint = ttk.Label(
            f,
            text=(
                "Creates: <name>.crt (certificate only), <name>.key (private key) and - if a chain is given -\n"
                "<name>-chain.crt and <name>-fullchain.crt (certificate + chain). Leave the password empty for\n"
                "an unencrypted key, which most web servers require."
            ),
            foreground="gray",
            justify="left",
        )
        self.pem_hint.grid(row=11, column=0, columnspan=3, sticky="w")
        self.pem_hint.grid_remove()

        self.p_btn = ttk.Button(f, text="Create PFX...", command=self._make_output)
        self.p_btn.grid(row=12, column=0, sticky="w", pady=10)
        self.p_status = tk.StringVar()
        ttk.Label(f, textvariable=self.p_status, foreground="#555", wraplength=720).grid(
            row=13, column=0, columnspan=3, sticky="w"
        )

    def _update_fmt(self) -> None:
        if self.p_fmt.get() == "pfx":
            self.pw_label.config(text="PFX password:")
            self.p_btn.config(text="Create PFX...")
            self.legacy_cb.grid()
            self.pem_hint.grid_remove()
        else:
            self.pw_label.config(text="Key password (optional):")
            self.p_btn.config(text="Create CRT + KEY...")
            self.legacy_cb.grid_remove()
            self.pem_hint.grid()

    def _write_pem_set(self, files: dict[str, bytes], default_stem: str) -> str | None:
        """Ask for a base name and write the PEM files next to each other.

        Returns a status message, or None if the user cancelled.
        """
        path = filedialog.asksaveasfilename(
            title="Save CRT + KEY (choose folder and base name)",
            defaultextension=".crt",
            initialfile=default_stem + ".crt",
            filetypes=[("Certificate", "*.crt"), ("All files", "*.*")],
        )
        if not path:
            return None
        base = Path(path)
        base_stem = base.name[: -len(base.suffix)] if base.suffix else base.name
        suffix = {"crt": ".crt", "key": ".key", "chain": "-chain.crt", "fullchain": "-fullchain.crt"}
        targets = {k: base.with_name(base_stem + suffix[k]) for k in files}
        existing = [t.name for k, t in targets.items() if k != "crt" and t.exists()]
        if existing and not messagebox.askyesno(
            "Files exist", "The following files already exist and will be overwritten:\n\n"
            + "\n".join(existing) + "\n\nContinue?"
        ):
            return None
        for k, t in targets.items():
            t.write_bytes(files[k])
        return "Saved: " + ", ".join(t.name for t in targets.values()) + f"\nin {base.parent}"

    def _make_output(self) -> None:
        if not self.p_cert.get() or not self.p_key.get():
            messagebox.showerror("Error", "Select both a certificate and a private key.")
            return
        pem = self.p_fmt.get() == "pem"
        if not pem and not self.p_pfxpw.get():
            messagebox.showerror("Error", "Enter a password for the PFX file (IIS requires one on import).")
            return
        if self.p_pfxpw.get() != self.p_pfxpw2.get():
            messagebox.showerror("Error", "The passwords do not match.")
            return
        if pem and not self.p_pfxpw.get() and not messagebox.askyesno(
            "No password",
            "The key file (.key) will be saved UNENCRYPTED. Anyone with access to the file can use it.\n\nContinue?",
        ):
            return
        try:
            cert = Path(self.p_cert.get()).read_bytes()
            key = Path(self.p_key.get()).read_bytes()
            chain = Path(self.p_chain.get()).read_bytes() if self.p_chain.get() else None
            if pem:
                files = csrgen.build_pem_files(cert, key, self.p_keypw.get(), chain, self.p_pfxpw.get())
            else:
                pfx = csrgen.build_pfx(
                    cert, key, self.p_keypw.get(), chain, self.p_pfxpw.get(),
                    self.p_name.get(), self.p_legacy.get(),
                )
        except csrgen.CsrError as exc:
            messagebox.showerror("Error", str(exc))
            return
        except OSError as exc:
            messagebox.showerror("Error", f"Could not read file: {exc}")
            return

        stem = Path(self.p_cert.get()).stem
        if pem:
            msg = self._write_pem_set(files, stem)
            if msg:
                self.p_status.set(msg)
            return
        path = filedialog.asksaveasfilename(
            title="Save PFX",
            defaultextension=".pfx",
            initialfile=stem + ".pfx",
            filetypes=[("PFX", "*.pfx"), ("All files", "*.*")],
        )
        if path:
            Path(path).write_bytes(pfx)
            self.p_status.set(f"PFX saved: {path}")

    def _on_close(self) -> None:
        unsaved = []
        if self.result is not None and not self.key_saved:
            unsaved.append("the private key for the generated CSR")
        if self.ss_result is not None and not self.ss_saved:
            unsaved.append("the generated self-signed certificate and its key")
        if unsaved and not messagebox.askyesno(
            "Not saved",
            "You have not saved " + " or ".join(unsaved) + ". They will be lost if you close now."
            "\n\nClose anyway?",
        ):
            return
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
