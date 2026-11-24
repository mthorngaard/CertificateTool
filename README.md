# CertificateTool

A small desktop GUI (Python/Tkinter) for everyday certificate work. English and Danish (Dansk) user interface.

1. **Create CSR**: generates a CSR you can paste into a certificate provider's admin portal, using the same fields as IIS' *Create Certificate Request* wizard. Can reuse an existing private key (renewal).
2. **Self-signed**: creates a self-signed TLS server certificate (for test, internal or development use).
3. **Local CA**: creates a small root CA and signs CSRs with it, so clients only need to trust one certificate.
4. **Export (PFX / CRT+KEY)**: turns an issued certificate plus its private key into a **PFX** or **CRT + KEY** files, with sanity checks.
5. **PFX to PEM**: converts a `.pfx` / `.p12` file back to `.crt` + `.key` (+ chain) files.
6. **Inspect**: shows subject, SANs, expiry, key, signature and fingerprints of a certificate or CSR.

Everything runs locally. Nothing is sent over the network, except if you explicitly tick *Download missing intermediate certificates* on the export tab.

## Get started

### Option A: Windows, no Python needed (portable)

1. Download `CertificateTool-windows-x64.zip` from the [latest release](https://github.com/mthorngaard/CertificateTool/releases/latest).
2. If Windows marks the download as blocked, right-click the zip > **Properties** > tick **Unblock** > OK, *before* extracting.
3. Extract the zip anywhere and double-click `CertificateTool.bat`.

No installation, administrator rights or code-signing certificate are needed. The bundle contains the official Python build from python.org (signed by the Python Software Foundation) plus the app's plain Python source files, so there is no unsigned `.exe` to trigger SmartScreen. You can rebuild the zip yourself with `scripts\build-portable.ps1` (see below).

> Locked-down machines that use AppLocker/WDAC may still block running scripts or Python from user folders. That depends on your organisation's policy.

### Option B: run from source (Windows, macOS, Linux)

Requirements:

- Python 3.10+ with Tkinter (included with the standard Windows/macOS installers; on Debian/Ubuntu run `apt install python3-tk`). On Windows, tick *Add python.exe to PATH* when installing.
- The [`cryptography`](https://pypi.org/project/cryptography/) package. [`tkinterdnd2`](https://pypi.org/project/tkinterdnd2/) is optional and enables drag and drop of files onto the file fields.

```
pip install -r requirements.txt
python app.py
```

On Windows you can also double-click `start.bat`, which checks Python/Tkinter, installs the dependencies if needed and starts the app (it falls back to the `py` launcher if `python` is not on PATH).

### Language, settings and profiles

The language follows your system (Danish or English). Change it under **Language** in the menu; it applies the next time you start the program.

The tool remembers the last used Organization, Unit, City, State, Country and key settings, and you can save named **profiles** of them (type a name in the *Profile* field and click *Save profile*). These are stored in `%APPDATA%\CertificateTool\settings.json` (`~/.config/certificatetool/settings.json` on Linux/macOS). Common names, SANs, passwords and keys are never stored.

**File > Clear all keys, passwords and results** wipes everything held in memory. Passwords are also cleared from the fields after a file has been saved.

### Running the tests

```
pip install -r requirements-dev.txt
python -m pytest
```

The GUI tests need a display (on Linux CI they run under `xvfb`) and are skipped if none is available. GitHub Actions runs the tests on Windows, Linux and macOS (`.github/workflows/ci.yml`).

### Building the portable zip

```
powershell -ExecutionPolicy Bypass -File scripts\build-portable.ps1
```

The script downloads the pinned Python release from python.org, verifies its SHA-256 hash, installs the dependencies from `requirements-build.txt` (exact versions with SHA-256 hashes, installed with `--require-hashes`), runs a smoke test of the real GUI and writes `CertificateTool-windows-x64.zip` to `%LOCALAPPDATA%\CertificateTool-build` (override with `-OutDir`).

When you change `requirements.txt`, refresh the lock file with `scripts\lock-build-requirements.ps1`.

**Releases:** bump `version.py`, commit, then push a tag such as `v1.1.0`. `.github/workflows/release.yml` runs the tests, builds the zip and attaches it to a GitHub release.

## 1. Create a CSR

Open the **Create CSR** tab and fill in:

| Field | Notes |
|---|---|
| Common name | e.g. `www.example.com` or `*.example.com` |
| Organization | Full legal company name |
| Organizational unit | e.g. `IT` |
| City/locality | |
| State/province | Spell it out, no abbreviations |
| Country/region | 2-letter code, e.g. `DK` |
| Key type / Bit length / Hash | RSA 2048/3072/4096, ECDSA P-256/384/521 or Ed25519; SHA-256/384/512 |
| Subject Alternative Names | Optional, one per line (DNS names, IPs, e-mail). The Common name is added automatically if it is a hostname |
| Password | Optional, encrypts the private key file |

Ed25519 is modern and fast, but not supported by IIS/Windows Server or many commercial CAs; use RSA or ECDSA for those.

Then:

1. Click **Generate CSR** (the key is generated in the background, so the window stays responsive for RSA 4096).
2. Click **Save private key...** and store the file safely. **The private key only exists in memory until you save it.** If you close the app without saving it, the certificate you get back cannot be used, and you need a new CSR.
3. Click **Copy CSR** and paste it into the CA's portal (or **Save CSR...** to keep a copy).

**Renewal:** tick *Use an existing private key* under **Renewal** and select your existing key file to make a new CSR for the same key.

You do not need the CSR file itself to build a PFX later, only the issued certificate and the private key.

## 2. Create a self-signed certificate

Open the **Self-signed** tab. It has the same Distinguished Name, key type, hash and SAN fields as the CSR tab, plus:

- **Valid for (days)**: default 365. You are warned above 825 days, because Apple platforms and other clients reject longer-lived TLS certificates.
- **Password**: protects the `.key` file (optional) or the PFX (required, IIS needs one on import).

Click **Generate certificate**, then save it with **Save CRT + KEY...** (PEM, for nginx/Apache etc.) or **Save PFX...** (IIS/Windows). The certificate is a TLS server certificate (Server Authentication, not a CA) with the SANs you entered, so add every hostname or IP clients will use.

Clients will not trust a self-signed certificate by default. Import it into the client's trusted root store, or accept the warning, for testing. If you need many certificates, use a local CA instead.

## 3. Local CA

The **Local CA** tab has two pages:

1. **Create CA**: fills in a name for the CA, creates a root certificate (CA, path length 0) and saves `<name>.crt` and `<name>.key`. Protect the CA key with a password and keep it safe. Install the `.crt` as a trusted root certificate on your clients, once.
2. **Sign a CSR**: select a CSR (from the *Create CSR* tab or another system), the CA certificate and CA key. The tool issues a TLS server certificate with the CSR's subject and SANs, saves `<name>.crt`, `<name>-chain.crt` and `<name>-fullchain.crt`, and shortens the validity if it would outlive the CA certificate.

To get a PFX for the issued certificate, combine the `.crt` with the CSR's private key on the **Export** tab.

## 4. Export the issued certificate

When the CA has issued the certificate, open the **Export** tab:

1. Select the certificate (`.cer`, `.crt`, `.pem` or `.p7b`).
2. Select the private key saved in step 1 (and its password, if you set one).
3. Optionally select the intermediate/root certificates from the CA, or tick *Download missing intermediate certificates* to fetch them from the certificate's *Authority Information Access* URL (the only feature that uses the network).
4. Choose the output format:
   - **PFX**: for IIS (*Server Certificates > Import*) and other Windows software. A password is required. Tick the compatibility option for Windows Server 2016 and older.
   - **CRT + KEY (PEM)**: for nginx, Apache and similar. Creates `<name>.crt`, `<name>.key` and, if a chain was supplied, `<name>-chain.crt` and `<name>-fullchain.crt`. Leave the password empty for an unencrypted key, which most web servers need.

The tool checks that the certificate matches the private key, and warns (you can still continue) if a certificate is expired or expires within 30 days, if the SAN is missing or if the intermediate certificate is not available.

Files and the PFX can be selected by dragging them onto the file fields (when `tkinterdnd2` is installed, which it is in the portable zip).

## 5. PFX to PEM

Select a `.pfx` / `.p12` file and its password. The tool writes `<name>.crt`, `<name>.key` and, if the PFX contains a chain, `<name>-chain.crt` and `<name>-fullchain.crt`. Set a new key password or leave it empty for an unencrypted key.

## 6. Inspect

Select a certificate or CSR file, or paste PEM text, and click **Inspect** to see subject, issuer, validity (and days left), key type, signature algorithm, SANs, key usage, CA flag and SHA-256 / SHA-1 fingerprints. A file containing several certificates (a chain or a `.p7b`) shows each of them.

## Security notes

- Treat the private key (`.key`) and `.pfx` files like passwords. Do not share or commit them. The included `.gitignore` excludes common certificate and key file types.
- On Linux and macOS, key and PFX files are written with permissions `0600`. On Windows the folder's permissions are kept, because keys are often exported for a service account (IIS, nginx, ...) to read; place them in a folder with the right access.
- An unencrypted key can be used by anyone who can read the file. Set a password unless the target system requires otherwise.
- The tool warns before discarding a generated key that has not been saved, and before saving an unencrypted key.

## Project layout

- `app.py`: main window, menu, background jobs
- `tab_csr.py`, `tab_selfsigned.py`, `tab_ca.py`, `tab_export.py`, `tab_convert.py`, `tab_inspect.py`: one module per tab
- `ui_common.py`: shared GUI parts (form with profiles, file fields, drag and drop, file output)
- `csrgen.py`: all certificate logic (CSR, self-signed, local CA, PFX/PEM, inspection), no GUI code
- `i18n.py`, `translations_da.py`: translations (a test checks that every string has a Danish translation)
- `settings.py`: remembered values and profiles; `version.py`: version number
- `tests/`: pytest tests (logic, GUI flows, translations, AIA download)
- `scripts/build-portable.ps1`, `scripts/lock-build-requirements.ps1`, `scripts/smoke_test.py`: portable build
- `.github/workflows/`: CI and release automation

## License

MIT, see [LICENSE](LICENSE).
