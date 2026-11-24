"""End-to-end GUI tests. Skipped automatically when no display is available."""

import gc
import time
import tkinter as tk
from tkinter import filedialog, messagebox

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

import csrgen
import settings


@pytest.fixture()
def app(monkeypatch):
    import app as app_module

    try:
        a = app_module.App()
    except tk.TclError as exc:  # no display (headless CI)
        pytest.skip(f"no display: {exc}")
    a.withdraw()
    yield a
    a.busy = 0
    try:
        a.destroy()
    except tk.TclError:
        pass  # already closed by the test
    # Collect leftover Tk variables on the main thread: finalising them from a worker thread
    # (where the next test's key generation runs) raises "main thread is not in main loop".
    gc.collect()


@pytest.fixture()
def dialogs(monkeypatch):
    class Recorder:
        errors: list[str] = []
        asked: list[str] = []
        save_paths: list[str] = []
        yes = True

    rec = Recorder()
    rec.errors, rec.asked, rec.save_paths = [], [], []
    monkeypatch.setattr(messagebox, "showerror", lambda title, msg, **k: rec.errors.append(msg))
    monkeypatch.setattr(messagebox, "showinfo", lambda *a, **k: None)

    def askyesno(title, msg, **k):
        rec.asked.append(title)
        return rec.yes

    monkeypatch.setattr(messagebox, "askyesno", askyesno)
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **k: rec.save_paths.pop(0))
    return rec


def wait(app):
    deadline = time.time() + 60
    while app.busy and time.time() < deadline:
        app.update()
        time.sleep(0.01)
    app.update()
    assert not app.busy


def test_csr_flow(app, dialogs, tmp_path):
    t = app.csr_tab
    t.form.v_cn.set("gui.example.com")
    t.form.v_o.set("GUI Test A/S")
    t.generate()
    wait(app)
    assert not dialogs.errors
    pem = t.out.get("1.0", "end")
    assert "BEGIN CERTIFICATE REQUEST" in pem
    assert t.unsaved()

    key_path = tmp_path / "gui.key"
    dialogs.save_paths.append(str(key_path))
    t.v_keypw.set("pw1")
    t.v_keypw2.set("pw1")
    t.save_key()
    assert b"ENCRYPTED" in key_path.read_bytes()
    assert t.unsaved() is None and t.v_keypw.get() == ""  # password cleared after saving

    csr_path = tmp_path / "gui.csr"
    dialogs.save_paths.append(str(csr_path))
    t.save_csr()
    assert x509.load_pem_x509_csr(csr_path.read_bytes()).is_signature_valid


def test_csr_password_mismatch_blocks_generation(app, dialogs):
    t = app.csr_tab
    t.form.v_cn.set("gui.example.com")
    t.v_keypw.set("a")
    t.v_keypw2.set("b")
    t.generate()
    assert dialogs.errors and t.result is None


def test_csr_reuses_existing_key(app, dialogs, tmp_path):
    first = csrgen.generate_csr(csrgen.CsrRequest(common_name="old.example.com", key_algorithm="ECDSA", key_size="P-256"))
    key_file = tmp_path / "old.key"
    key_file.write_bytes(csrgen.private_key_to_pem(first.private_key, "oldpw"))
    t = app.csr_tab
    t.v_reuse.set(True)
    t._toggle_reuse()
    t.v_exkey.set(str(key_file))
    t.v_exkey_pw.set("oldpw")
    t.form.v_cn.set("old.example.com")
    t.generate()
    wait(app)
    assert not dialogs.errors
    assert t.result.reused_key and t.unsaved() is None
    csr = x509.load_pem_x509_csr(t.result.csr_pem.encode())
    assert csr.public_key().public_numbers() == first.private_key.public_key().public_numbers()


def test_self_signed_flow_and_long_validity_warning(app, dialogs, tmp_path):
    t = app.ss_tab
    t.form.v_cn.set("ss.example.com")
    t.v_days.set("2000")
    dialogs.yes = False
    t.generate()
    assert "Long validity" in dialogs.asked and t.result is None
    dialogs.yes = True
    t.generate()
    wait(app)
    assert not dialogs.errors and t.result is not None

    t.v_pw.set("pfxpw")
    t.v_pw2.set("pfxpw")
    pfx_path = tmp_path / "ss.pfx"
    dialogs.save_paths.append(str(pfx_path))
    t.save_pfx()
    key, cert, _extra = pkcs12.load_key_and_certificates(pfx_path.read_bytes(), b"pfxpw")
    assert key is not None and cert is not None
    assert t.unsaved() is None

    t.v_pw.set("keypw")
    t.v_pw2.set("keypw")
    dialogs.save_paths.append(str(tmp_path / "ss.crt"))
    t.save_pem()
    assert (tmp_path / "ss.key").exists() and b"ENCRYPTED" in (tmp_path / "ss.key").read_bytes()


def test_ca_sign_export_convert_inspect(app, dialogs, tmp_path):
    # 1. create CA
    ca = app.ca_tab
    ca.form.v_cn.set("GUI Test CA")
    ca.v_pw.set("capw")
    ca.v_pw2.set("capw")
    dialogs.save_paths.append(str(tmp_path / "ca.crt"))
    ca.create_ca()
    wait(app)
    assert not dialogs.errors and ca.unsaved() is None
    assert (tmp_path / "ca.crt").exists() and (tmp_path / "ca.key").exists()

    # 2. CSR with a fresh key, saved to disk
    c = app.csr_tab
    c.form.v_cn.set("srv.example.com")
    c.generate()
    wait(app)
    (tmp_path / "srv.csr").write_text(c.result.csr_pem)
    (tmp_path / "srv.key").write_bytes(csrgen.private_key_to_pem(c.result.private_key))

    # 3. sign with the CA
    ca.v_csr.set(str(tmp_path / "srv.csr"))
    ca.v_ca_cert.set(str(tmp_path / "ca.crt"))
    ca.v_ca_key.set(str(tmp_path / "ca.key"))
    ca.v_sign_pw.set("capw")
    dialogs.save_paths.append(str(tmp_path / "srv.crt"))
    ca.sign()
    assert not dialogs.errors
    assert (tmp_path / "srv.crt").exists() and (tmp_path / "srv-fullchain.crt").exists()

    # 4. export to PFX (chain = CA cert), no warnings expected
    e = app.export_tab
    e.v_cert.set(str(tmp_path / "srv.crt"))
    e.v_key.set(str(tmp_path / "srv.key"))
    e.v_chain.set(str(tmp_path / "ca.crt"))
    e.v_pw.set("pfxpw")
    e.v_pw2.set("pfxpw")
    dialogs.asked.clear()
    dialogs.save_paths.append(str(tmp_path / "srv.pfx"))
    e.make_output()
    assert not dialogs.errors and "Warnings" not in dialogs.asked
    assert (tmp_path / "srv.pfx").exists()
    assert e.v_pw.get() == ""  # cleared after saving

    # 5. convert the PFX back to PEM files
    v = app.convert_tab
    v.v_pfx.set(str(tmp_path / "srv.pfx"))
    v.v_pfxpw.set("pfxpw")
    dialogs.save_paths.append(str(tmp_path / "back.crt"))
    dialogs.asked.clear()
    v.convert()  # empty output password -> asks to confirm unencrypted key (yes)
    assert not dialogs.errors
    assert (tmp_path / "back.key").exists() and (tmp_path / "back-fullchain.crt").exists()

    # 6. inspect
    i = app.inspect_tab
    i.v_file.set(str(tmp_path / "srv-fullchain.crt"))
    i.inspect()
    text = i.out.get("1.0", "end")
    assert "srv.example.com" in text and "GUI Test CA" in text


def test_export_warns_when_chain_missing(app, dialogs, tmp_path):
    ca = csrgen.generate_ca(csrgen.CsrRequest(common_name="C"), 30)
    csr = csrgen.generate_csr(csrgen.CsrRequest(common_name="w.example.com"))
    signed = csrgen.sign_csr(
        csr.csr_pem.encode(), ca.cert_pem.encode(), csrgen.private_key_to_pem(ca.private_key), "", 30
    )
    (tmp_path / "w.crt").write_text(signed.cert_pem)
    (tmp_path / "w.key").write_bytes(csrgen.private_key_to_pem(csr.private_key))
    e = app.export_tab
    e.v_cert.set(str(tmp_path / "w.crt"))
    e.v_key.set(str(tmp_path / "w.key"))
    e.v_pw.set("x")
    e.v_pw2.set("x")
    dialogs.yes = False  # decline at the warning
    e.make_output()
    assert "Warnings" in dialogs.asked
    assert not (tmp_path / "w.pfx").exists()


def test_ed25519_disables_hash_and_size(app):
    f = app.csr_tab.form
    f.v_alg.set("Ed25519")
    f._update_sizes()
    assert str(f.hash_box.cget("state")) == "disabled"
    assert str(f.size_box.cget("state")) == "disabled"
    f.v_alg.set("RSA")
    f._update_sizes()
    assert str(f.hash_box.cget("state")) == "readonly"
    assert f.v_size.get() == "2048"


def test_profiles_and_last_used(app, dialogs):
    f = app.ss_tab.form
    f.v_o.set("Profile Corp")
    f.v_l.set("Aarhus")
    f.v_profile.set("work")
    f._save_profile()
    assert settings.get_profiles()["work"]["o"] == "Profile Corp"
    f.v_o.set("")
    f.v_profile.set("work")
    f._load_profile()
    assert f.v_o.get() == "Profile Corp" and f.v_l.get() == "Aarhus"
    dialogs.yes = True
    f._delete_profile()
    assert "work" not in settings.get_profiles()

    f.v_cn.set("remember.example.com")
    app.ss_tab.generate()
    wait(app)
    assert settings.get_last_used()["o"] == "Profile Corp"


def test_danish_ui_builds_and_dnd_loads(monkeypatch):
    import app as app_module
    import i18n
    import ui_common

    try:
        i18n.set_language("da")
        try:
            a = app_module.App()
        except tk.TclError as exc:
            pytest.skip(f"no display: {exc}")
        a.withdraw()
        try:
            nb = [w for w in a.winfo_children() if w.winfo_class() == "TNotebook"][0]
            titles = [nb.tab(i, "text") for i in range(nb.index("end"))]
            assert "Opret CSR" in titles and "Inspicér" in titles
            if ui_common.HAS_DND:
                assert a.dnd_ok
        finally:
            a.destroy()
            gc.collect()
    finally:
        i18n.set_language("en")


def test_clear_all_resets_everything(app, dialogs):
    app.csr_tab.form.v_cn.set("x.example.com")
    app.csr_tab.generate()
    wait(app)
    assert app.unsaved_summary()
    dialogs.yes = True
    app.clear_all()
    assert app.csr_tab.result is None and not app.unsaved_summary()
    assert app.csr_tab.form.v_cn.get() == ""


def test_close_asks_when_unsaved(app, dialogs):
    app.csr_tab.form.v_cn.set("x.example.com")
    app.csr_tab.generate()
    wait(app)
    dialogs.yes = False
    app._on_close()
    assert app.winfo_exists()
    dialogs.yes = True
    app._on_close()
