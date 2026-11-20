# CertificateTool

A small desktop GUI (Python/Tkinter) that generates a **CSR** you can paste into a certificate provider's admin portal. It uses the same fields as IIS' *Create Certificate Request* wizard, and it can turn the issued certificate into a **PFX** or **CRT + KEY** files afterwards.

Everything runs locally. Nothing is sent over the network.

## Requirements

- Windows, macOS or Linux with Python 3.9+ (Tkinter is included with the standard Windows/macOS installers)
- The [`cryptography`](https://pypi.org/project/cryptography/) package

## Run

```
pip install -r requirements.txt
python app.py
```

On Windows you can also double-click `start.bat`, which installs the dependency if needed and starts the app.

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
| Key type / Bit length / Hash | RSA 2048/3072/4096 or ECDSA P-256/384/521; SHA-256/384/512 |
| Subject Alternative Names | Optional, one per line (DNS names, IPs, e-mail). The Common name is added automatically if it is a hostname |
| Password | Optional, encrypts the private key file |

Then:

1. Click **Generate CSR**.
2. Click **Save private key...** and store the file safely. **The private key only exists in memory until you save it.** If you close the app without saving it, the certificate you get back cannot be used, and you need a new CSR.
3. Click **Copy CSR** and paste it into the CA's portal (or **Save CSR...** to keep a copy).

You do not need the CSR file itself to build a PFX later, only the issued certificate and the private key.

## 2. Export the issued certificate

When the CA has issued the certificate, open the **Export certificate** tab:

1. Select the certificate (`.cer`, `.crt`, `.pem` or `.p7b`).
2. Select the private key saved in step 1 (and its password, if you set one).
3. Optionally select the intermediate/root certificates from the CA.
4. Choose the output format:
   - **PFX**: for IIS (*Server Certificates > Import*) and other Windows software. A password is required. Tick the compatibility option for Windows Server 2016 and older.
   - **CRT + KEY (PEM)**: for nginx, Apache and similar. Creates `<name>.crt`, `<name>.key` and, if a chain was supplied, `<name>-chain.crt` and `<name>-fullchain.crt`. Leave the password empty for an unencrypted key, which most web servers need.

The tool checks that the certificate matches the private key before exporting.

## Security notes

- Treat the private key (`.key`) and `.pfx` files like passwords. Do not share or commit them. The included `.gitignore` excludes common certificate and key file types.
- An unencrypted key can be used by anyone who can read the file. Set a password unless the target system requires otherwise.

## Project layout

- `app.py`: the GUI
- `csrgen.py`: CSR generation and PFX/PEM export, no GUI code

## License

MIT, see [LICENSE](LICENSE).
