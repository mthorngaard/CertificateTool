"""Shared GUI building blocks (form, file rows, password entries, drag and drop, file output)."""

from __future__ import annotations

import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import csrgen
import settings
from i18n import _

try:  # optional: drag and drop of files onto the file fields
    from tkinterdnd2 import DND_FILES, TkinterDnD

    HAS_DND = True
except Exception:  # pragma: no cover - depends on the environment
    DND_FILES = TkinterDnD = None
    HAS_DND = False

COUNTRIES = [
    "DK", "SE", "NO", "FI", "IS", "DE", "NL", "BE", "FR", "GB", "IE", "ES", "IT",
    "PL", "AT", "CH", "US", "CA", "GL", "FO",
]

def cert_types():
    return [(_("Certificates"), "*.cer *.crt *.pem *.p7b *.p7c"), (_("All files"), "*.*")]


def key_types():
    return [(_("Private key"), "*.key *.pem"), (_("All files"), "*.*")]


def csr_types():
    return [(_("Certificate request"), "*.csr *.pem *.txt"), (_("All files"), "*.*")]


def pfx_types():
    return [("PFX / PKCS#12", "*.pfx *.p12"), (_("All files"), "*.*")]


def safe_name(common_name: str) -> str:
    name = common_name.strip().replace("*", "wildcard")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "certificate"


def px(widget: tk.Misc, pixels: int) -> int:
    """Scale a 96-DPI pixel size to the current display scaling."""
    return int(pixels * widget.winfo_fpixels("1i") / 96)


def enable_dnd(root: tk.Tk) -> bool:
    """Load the tkdnd extension into this interpreter. Returns False if unavailable."""
    if not HAS_DND:
        return False
    try:
        require = getattr(TkinterDnD, "require", None) or TkinterDnD._require
        require(root)
        return True
    except Exception:  # pragma: no cover
        return False


def add_file_drop(widget: tk.Misc, var: tk.StringVar) -> None:
    """Let the user drop a file on `widget` to fill `var` (no-op without tkinterdnd2/tkdnd)."""
    if not getattr(widget.winfo_toplevel(), "dnd_ok", False):
        return
    try:
        widget.drop_target_register(DND_FILES)

        def _drop(event) -> str:
            files = widget.tk.splitlist(event.data)
            if files:
                var.set(files[0])
            return "copy"

        widget.dnd_bind("<<Drop>>", _drop)
    except Exception:  # pragma: no cover
        pass


def file_row(parent: tk.Misc, row: int, label: str, var: tk.StringVar, types) -> ttk.Entry:
    """Label + entry + Browse button (also a drop target)."""
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
    entry = ttk.Entry(parent, textvariable=var)
    entry.grid(row=row, column=1, sticky="ew", padx=6)
    ttk.Button(
        parent,
        text=_("Browse..."),
        command=lambda: var.set(filedialog.askopenfilename(filetypes=types) or var.get()),
    ).grid(row=row, column=2)
    add_file_drop(entry, var)
    return entry


def password_entry(parent: tk.Misc, var: tk.StringVar, width: int = 24) -> ttk.Frame:
    """Password field with a 'Show' checkbox."""
    frame = ttk.Frame(parent)
    entry = ttk.Entry(frame, textvariable=var, show="*", width=width)
    entry.pack(side="left")
    shown = tk.BooleanVar(value=False)

    def toggle() -> None:
        entry.config(show="" if shown.get() else "*")

    ttk.Checkbutton(frame, text=_("Show"), variable=shown, command=toggle).pack(side="left", padx=(6, 0))
    return frame


def status_label(parent: tk.Misc, var: tk.StringVar, row: int, columnspan: int = 2) -> ttk.Label:
    lbl = ttk.Label(parent, textvariable=var, foreground="#555", wraplength=px(parent, 720))
    lbl.grid(row=row, column=0, columnspan=columnspan, sticky="w", pady=(6, 0))
    return lbl


def make_output_box(parent: tk.Misc, row: int, title: str) -> tk.Text:
    out = ttk.LabelFrame(parent, text=title, padding=8)
    out.grid(row=row, column=0, columnspan=2, sticky="nsew")
    parent.rowconfigure(row, weight=1)
    out.columnconfigure(0, weight=1)
    out.rowconfigure(0, weight=1)
    box = tk.Text(out, height=5, font=("Consolas", 9), wrap="none")
    box.grid(row=0, column=0, sticky="nsew")
    sb = ttk.Scrollbar(out, command=box.yview)
    sb.grid(row=0, column=1, sticky="ns")
    box.configure(yscrollcommand=sb.set)
    return box


def set_text(box: tk.Text, text: str) -> None:
    box.delete("1.0", "end")
    box.insert("1.0", text)


def copy_to_clipboard(widget: tk.Misc, text: str) -> None:
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update()


def passwords_match(a: str, b: str) -> bool:
    if a != b:
        messagebox.showerror(_("Error"), _("The passwords do not match."))
        return False
    return True


def confirm_unencrypted_key() -> bool:
    return messagebox.askyesno(
        _("No password"),
        _("The private key will be saved UNENCRYPTED. Anyone with access to the file can use it.")
        + "\n\n" + _("Continue?"),
    )


def confirm_warnings(warnings: list[str], notes: list[str] | None = None) -> bool:
    """Show export warnings; True means 'continue'."""
    if not warnings:
        return True
    body = "\n".join("- " + w for w in warnings)
    if notes:
        body += "\n\n" + "\n".join(notes)
    return messagebox.askyesno(_("Warnings"), body + "\n\n" + _("Continue anyway?"), icon="warning")


def save_file_dialog(title: str, ext: str, stem: str, types) -> str:
    return filedialog.asksaveasfilename(
        title=title, defaultextension=ext, initialfile=stem + ext, filetypes=types
    )


def write_pem_set(files: dict[str, bytes], default_stem: str, title: str | None = None) -> str | None:
    """Ask for a base name and write the PEM files next to each other.

    Returns a status message, or None if the user cancelled.
    """
    path = filedialog.asksaveasfilename(
        title=title or _("Save CRT + KEY (choose folder and base name)"),
        defaultextension=".crt",
        initialfile=default_stem + ".crt",
        filetypes=[(_("Certificate"), "*.crt"), (_("All files"), "*.*")],
    )
    if not path:
        return None
    base = Path(path)
    base_stem = base.name[: -len(base.suffix)] if base.suffix else base.name
    suffix = {"crt": ".crt", "key": ".key", "chain": "-chain.crt", "fullchain": "-fullchain.crt"}
    targets = {k: base.with_name(base_stem + suffix[k]) for k in files}
    existing = [t.name for k, t in targets.items() if k != "crt" and t.exists()]
    if existing and not messagebox.askyesno(
        _("Files exist"),
        _("The following files already exist and will be overwritten:") + "\n\n"
        + "\n".join(existing) + "\n\n" + _("Continue?"),
    ):
        return None
    for k, t in targets.items():
        if k == "key":
            csrgen.write_private_file(t, files[k])
        else:
            t.write_bytes(files[k])
    return _("Saved: {names}\nin {folder}").format(
        names=", ".join(t.name for t in targets.values()), folder=base.parent
    )


class CertForm(ttk.Frame):
    """Profile bar + DN fields + cryptography + SAN. Shared by the CSR, self-signed and CA tabs."""

    def __init__(self, master, show_san: bool = True, dn_title: str | None = None) -> None:
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
        self.v_profile = tk.StringVar()

        # ---- profiles
        prof = ttk.Frame(self)
        prof.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(prof, text=_("Profile:")).pack(side="left")
        self.profile_box = ttk.Combobox(
            prof, textvariable=self.v_profile, values=list(settings.get_profiles()), width=24,
            postcommand=self._refresh_profiles,
        )
        self.profile_box.pack(side="left", padx=6)
        self.profile_box.bind("<<ComboboxSelected>>", lambda _e: self._load_profile())
        ttk.Button(prof, text=_("Save profile"), command=self._save_profile).pack(side="left")
        ttk.Button(prof, text=_("Delete"), command=self._delete_profile).pack(side="left", padx=6)

        # ---- DN
        grp = ttk.LabelFrame(self, text=dn_title or _("Distinguished Name (same as IIS)"), padding=8)
        grp.grid(row=1, column=0, sticky="ew")
        grp.columnconfigure(1, weight=1)

        rows = [
            (_("Common name:"), self.v_cn, _("e.g. www.example.com or *.example.com")),
            (_("Organization:"), self.v_o, _("Full legal name of the company")),
            (_("Organizational unit:"), self.v_ou, _("e.g. IT")),
            (_("City/locality:"), self.v_l, ""),
            (_("State/province:"), self.v_st, _("Spell it out in full, no abbreviations")),
        ]
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(grp, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ent = ttk.Entry(grp, textvariable=var)
            ent.grid(row=i, column=1, sticky="ew", padx=6, pady=2)
            ttk.Label(grp, text=hint, foreground="gray").grid(row=i, column=2, sticky="w")
            if i == 0:
                self.cn_entry = ent
        r = len(rows)
        ttk.Label(grp, text=_("Country/region:")).grid(row=r, column=0, sticky="w", pady=2)
        ttk.Combobox(grp, textvariable=self.v_c, values=COUNTRIES, width=6).grid(
            row=r, column=1, sticky="w", padx=6, pady=2
        )
        ttk.Label(grp, text=_("2-letter country code"), foreground="gray").grid(row=r, column=2, sticky="w")

        # ---- crypto
        self.crypto = crypto = ttk.LabelFrame(self, text=_("Cryptography"), padding=8)
        crypto.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(crypto, text=_("Key type:")).grid(row=0, column=0, sticky="w")
        alg = ttk.Combobox(
            crypto, textvariable=self.v_alg, values=csrgen.KEY_ALGORITHMS, state="readonly", width=8
        )
        alg.grid(row=0, column=1, padx=6)
        alg.bind("<<ComboboxSelected>>", lambda _e: self._update_sizes())
        self.size_label = ttk.Label(crypto, text=_("Bit length:"))
        self.size_label.grid(row=0, column=2, padx=(12, 0))
        self.size_box = ttk.Combobox(
            crypto, textvariable=self.v_size, values=csrgen.RSA_SIZES, state="readonly", width=8
        )
        self.size_box.grid(row=0, column=3, padx=6)
        ttk.Label(crypto, text=_("Hash:")).grid(row=0, column=4, padx=(12, 0))
        self.hash_box = ttk.Combobox(
            crypto, textvariable=self.v_hash, values=list(csrgen.HASHES), state="readonly", width=9
        )
        self.hash_box.grid(row=0, column=5, padx=6)
        self.ed_hint = ttk.Label(
            crypto,
            text=_("Ed25519 is modern and fast but not supported by IIS/Windows Server or many CAs."),
            foreground="gray",
        )
        self.ed_hint.grid(row=1, column=0, columnspan=6, sticky="w", pady=(4, 0))
        self.ed_hint.grid_remove()

        # ---- SAN
        self.san_text: tk.Text | None = None
        if show_san:
            san = ttk.LabelFrame(self, text=_("Subject Alternative Names (optional - one per line)"), padding=8)
            san.grid(row=3, column=0, sticky="ew", pady=(8, 0))
            san.columnconfigure(0, weight=1)
            self.san_text = tk.Text(san, height=3, width=40, wrap="word")
            self.san_text.grid(row=0, column=0, sticky="ew")
            ttk.Checkbutton(
                san, text=_("Include Common name as a SAN (recommended)"), variable=self.v_cn_san
            ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._apply_values(settings.get_last_used())

    # ------------------------------------------------------ profiles ----
    def profile_values(self) -> dict:
        return {
            "o": self.v_o.get(), "ou": self.v_ou.get(), "l": self.v_l.get(), "st": self.v_st.get(),
            "c": self.v_c.get(), "alg": self.v_alg.get(), "size": self.v_size.get(),
            "hash": self.v_hash.get(),
        }

    def _apply_values(self, values: dict) -> None:
        for key, var in (
            ("o", self.v_o), ("ou", self.v_ou), ("l", self.v_l), ("st", self.v_st), ("c", self.v_c),
        ):
            if key in values:
                var.set(values[key])
        if values.get("alg") in csrgen.KEY_ALGORITHMS:
            self.v_alg.set(values["alg"])
            self._update_sizes()
            valid = list(self.size_box.cget("values"))
            if values.get("size") in valid:
                self.v_size.set(values["size"])
        if values.get("hash") in csrgen.HASHES:
            self.v_hash.set(values["hash"])

    def _refresh_profiles(self) -> None:
        self.profile_box.config(values=list(settings.get_profiles()))

    def _load_profile(self) -> None:
        values = settings.get_profiles().get(self.v_profile.get())
        if values:
            self._apply_values(values)

    def _save_profile(self) -> None:
        name = self.v_profile.get().strip()
        if not name:
            messagebox.showerror(_("Error"), _("Type a name for the profile in the Profile field first."))
            return
        settings.save_profile(name, self.profile_values())
        self._refresh_profiles()

    def _delete_profile(self) -> None:
        name = self.v_profile.get().strip()
        if name in settings.get_profiles() and messagebox.askyesno(
            _("Delete profile"), _("Delete the profile '{name}'?").format(name=name)
        ):
            settings.delete_profile(name)
            self.v_profile.set("")
            self._refresh_profiles()

    def remember(self) -> None:
        """Store the non-sensitive fields as 'last used'."""
        settings.set_last_used(self.profile_values())

    # --------------------------------------------------------- crypto ----
    def _update_sizes(self) -> None:
        alg = self.v_alg.get()
        if alg == "RSA":
            self.size_label.config(text=_("Bit length:"))
            self.size_box.config(values=csrgen.RSA_SIZES, state="readonly")
            self.v_size.set("2048")
            self.hash_box.config(state="readonly")
            self.ed_hint.grid_remove()
        elif alg == "ECDSA":
            self.size_label.config(text=_("Curve:"))
            self.size_box.config(values=list(csrgen.EC_CURVES), state="readonly")
            self.v_size.set("P-256")
            self.hash_box.config(state="readonly")
            self.ed_hint.grid_remove()
        else:
            self.size_label.config(text=_("Curve:"))
            self.size_box.config(values=["Ed25519"], state="disabled")
            self.v_size.set("Ed25519")
            self.hash_box.config(state="disabled")
            self.ed_hint.grid()

    def set_crypto_enabled(self, enabled: bool) -> None:
        """Disable the key type controls (used when an existing key is reused)."""
        ed = self.v_alg.get() == "Ed25519"
        for child in self.crypto.winfo_children():
            if isinstance(child, ttk.Combobox):
                child.config(state="readonly" if enabled else "disabled")
        if enabled and ed:
            self.size_box.config(state="disabled")
            self.hash_box.config(state="disabled")

    def get_request(self, existing_key=None) -> csrgen.CsrRequest:
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
            san_entries=(
                csrgen.parse_san_text(self.san_text.get("1.0", "end")) if self.san_text else []
            ),
            include_cn_in_san=self.v_cn_san.get(),
            existing_key=existing_key,
        )

    def clear_sensitive(self) -> None:
        """Clear the per-certificate fields (keeps organisation defaults)."""
        self.v_cn.set("")
        if self.san_text:
            self.san_text.delete("1.0", "end")
