"""Smoke test used by build-portable.ps1 (no pytest needed).

Usage: python smoke_test.py <folder containing app.py>
Starts the real GUI, generates a CSR, a self-signed certificate and a local-CA certificate
(including the background key generation), and checks the optional drag-and-drop support.
"""

import os
import sys
import tempfile
import time
from tkinter import messagebox

app_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(app_dir))
os.environ.setdefault("CERTTOOL_CONFIG_DIR", tempfile.mkdtemp(prefix="certtool-smoke-"))

import app  # noqa: E402
import csrgen  # noqa: E402

messagebox.showerror = lambda *a, **k: (_ for _ in ()).throw(AssertionError(f"error dialog: {a}"))
messagebox.showinfo = lambda *a, **k: None
messagebox.askyesno = lambda *a, **k: True

a = app.App()
a.withdraw()


def wait() -> None:
    end = time.time() + 60
    while a.busy and time.time() < end:
        a.update()
        time.sleep(0.01)
    a.update()
    assert not a.busy, "background job did not finish"


a.ss_tab.form.v_cn.set("smoke.example.com")
a.ss_tab.generate()
wait()
assert "BEGIN CERTIFICATE" in a.ss_tab.out.get("1.0", "end")

a.csr_tab.form.v_cn.set("smoke.example.com")
a.csr_tab.generate()
wait()
assert "BEGIN CERTIFICATE REQUEST" in a.csr_tab.out.get("1.0", "end")

ca = csrgen.generate_ca(csrgen.CsrRequest(common_name="Smoke CA"), 30)
signed = csrgen.sign_csr(
    a.csr_tab.result.csr_pem.encode(), ca.cert_pem.encode(),
    csrgen.private_key_to_pem(ca.private_key), "", 30,
)
assert "BEGIN CERTIFICATE" in signed.cert_pem
assert "Smoke CA" in csrgen.inspect_data(signed.cert_pem.encode())

a.csr_tab.key_saved = a.ss_tab.saved = True
a.destroy()
print("ok (drag and drop: %s)" % ("available" if a.dnd_ok else "not available"))
