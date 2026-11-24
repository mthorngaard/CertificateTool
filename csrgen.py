"""Certificate logic: CSRs, self-signed certs, a small local CA, PFX/PEM export and inspection.

No GUI code here.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from i18n import _

PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]

RSA_SIZES = ["2048", "3072", "4096"]
EC_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
HASHES = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}
KEY_ALGORITHMS = ["RSA", "ECDSA", "Ed25519"]

# Max lengths per RFC 5280 (upper bounds) - the same limits IIS and CAs enforce
MAX_LEN = {"CN": 64, "O": 64, "OU": 64, "L": 128, "ST": 128}

MAX_VALIDITY_DAYS = 36500
# Apple platforms reject TLS server certs valid for more than 825 days (398 for public CAs)
RECOMMENDED_MAX_DAYS = 825
EXPIRY_WARNING_DAYS = 30


class CsrError(Exception):
    """Error with a user-friendly message."""


@dataclass
class CsrRequest:
    common_name: str
    organization: str = ""
    organizational_unit: str = ""
    locality: str = ""
    state: str = ""
    country: str = ""
    key_algorithm: str = "RSA"
    key_size: str = "2048"  # RSA: bit length, ECDSA: curve name, Ed25519: ignored
    hash_name: str = "SHA-256"
    san_entries: list[str] = field(default_factory=list)
    include_cn_in_san: bool = True
    existing_key: PrivateKey | None = field(default=None, repr=False)  # reuse a key (renewal)


@dataclass
class CsrResult:
    csr_pem: str
    private_key: PrivateKey
    subject: str
    sans: list[str]
    reused_key: bool = False


@dataclass
class SelfSignedResult:
    cert_pem: str
    private_key: PrivateKey
    subject: str
    sans: list[str]
    not_after: datetime.datetime


@dataclass
class SignedResult:
    cert_pem: str
    subject: str
    sans: list[str]
    not_after: datetime.datetime
    clamped: bool  # validity was shortened to the CA's own expiry


@dataclass
class ExportBundle:
    leaf: x509.Certificate
    chain: list[x509.Certificate]
    key: PrivateKey
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------ helpers ----

def parse_san_text(text: str) -> list[str]:
    """Split text into SAN entries (newline, comma, semicolon or whitespace)."""
    parts = re.split(r"[\s,;]+", text.strip())
    out: list[str] = []
    for p in parts:
        if p and p not in out:
            out.append(p)
    return out


_DNS_RE = re.compile(
    r"(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*"
)


def _san_to_general_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "@" in value:
        return x509.RFC822Name(value)
    original = value
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CsrError(_("Invalid domain name in SAN: {value}").format(value=original)) from exc
    if not _DNS_RE.fullmatch(value):
        raise CsrError(_("Invalid domain name in SAN: {value}").format(value=original))
    return x509.DNSName(value)


def _is_ed25519(key) -> bool:
    return isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey))


def key_description(key) -> str:
    """Human-readable key type for a private or public key."""
    pub = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size} bit"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA {pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(pub).__name__


def validate(req: CsrRequest) -> None:
    if not req.common_name.strip():
        raise CsrError(_("Common name is required."))
    values = {
        "CN": req.common_name,
        "O": req.organization,
        "OU": req.organizational_unit,
        "L": req.locality,
        "ST": req.state,
    }
    for key, val in values.items():
        if len(val.strip()) > MAX_LEN[key]:
            raise CsrError(_("{field} must be at most {n} characters.").format(field=key, n=MAX_LEN[key]))
    if req.country and not re.fullmatch(r"[A-Za-z]{2}", req.country.strip()):
        raise CsrError(_("Country/region must be a 2-letter country code (e.g. DK)."))
    for key, val in values.items():
        if "\n" in val or "\r" in val:
            raise CsrError(_("{field} must not contain line breaks.").format(field=key))
    if req.existing_key is None:
        if req.key_algorithm == "RSA":
            if req.key_size not in RSA_SIZES:
                raise CsrError(_("Invalid RSA bit length."))
        elif req.key_algorithm == "ECDSA":
            if req.key_size not in EC_CURVES:
                raise CsrError(_("Invalid ECDSA curve."))
        elif req.key_algorithm != "Ed25519":
            raise CsrError(_("Unknown key algorithm."))
    uses_hash = not (_is_ed25519(req.existing_key) if req.existing_key is not None
                     else req.key_algorithm == "Ed25519")
    if uses_hash and req.hash_name not in HASHES:
        raise CsrError(_("Invalid hash algorithm."))


def _generate_key(req: CsrRequest) -> PrivateKey:
    if req.existing_key is not None:
        return req.existing_key
    if req.key_algorithm == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(req.key_size))
    if req.key_algorithm == "Ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(EC_CURVES[req.key_size]())


def _hash_for(req: CsrRequest, key) -> hashes.HashAlgorithm | None:
    """Hash used for signing (None for Ed25519, which has a built-in hash)."""
    return None if _is_ed25519(key) else HASHES[req.hash_name]()


def _build_name(req: CsrRequest) -> x509.Name:
    attrs: list[x509.NameAttribute] = []
    # Same order as IIS/certreq: C, S, L, O, OU, CN
    if req.country.strip():
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, req.country.strip().upper()))
    if req.state.strip():
        attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, req.state.strip()))
    if req.locality.strip():
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, req.locality.strip()))
    if req.organization.strip():
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, req.organization.strip()))
    if req.organizational_unit.strip():
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, req.organizational_unit.strip()))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, req.common_name.strip()))
    return x509.Name(attrs)


def _collect_sans(req: CsrRequest) -> list[str]:
    sans: list[str] = []
    if req.include_cn_in_san:
        try:
            _san_to_general_name(req.common_name.strip())
            sans.append(req.common_name.strip())
        except CsrError:
            pass  # CN is not a hostname/IP, so it makes no sense as a SAN
    for s in req.san_entries:
        if s and s not in sans:
            sans.append(s)
    return sans


def _leaf_key_usage(public_key) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _check_days(days: int) -> None:
    if not 1 <= days <= MAX_VALIDITY_DAYS:
        raise CsrError(_("Validity must be between 1 and {max} days.").format(max=MAX_VALIDITY_DAYS))


# ---------------------------------------------------------------- CSR ----

def generate_csr(req: CsrRequest) -> CsrResult:
    validate(req)
    name = _build_name(req)
    sans = _collect_sans(req)

    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san_to_general_name(s) for s in sans]),
            critical=False,
        )

    key = _generate_key(req)
    csr = builder.sign(key, _hash_for(req, key))
    if not csr.is_signature_valid:  # pragma: no cover - sanity check
        raise CsrError(_("Internal error: the CSR signature is invalid."))

    return CsrResult(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        subject=csr.subject.rfc4514_string(),
        sans=sans,
        reused_key=req.existing_key is not None,
    )


# -------------------------------------------- self-signed and local CA ----

def _build_self_signed(req: CsrRequest, days: int, is_ca: bool) -> SelfSignedResult:
    validate(req)
    _check_days(days)
    name = _build_name(req)
    sans = [] if is_ca else _collect_sans(req)
    key = _generate_key(req)

    now = _utcnow()
    not_before = now - datetime.timedelta(minutes=5)  # tolerate small clock skew
    not_after = now + datetime.timedelta(days=days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = (
            builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_leaf_key_usage(key.public_key()), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san_to_general_name(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, _hash_for(req, key))
    return SelfSignedResult(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        subject=cert.subject.rfc4514_string(),
        sans=sans,
        not_after=not_after,
    )


def generate_self_signed(req: CsrRequest, days: int) -> SelfSignedResult:
    """Create a self-signed TLS server certificate (subject == issuer)."""
    return _build_self_signed(req, days, is_ca=False)


def generate_ca(req: CsrRequest, days: int) -> SelfSignedResult:
    """Create a self-signed root CA certificate (can sign server certificates, path length 0)."""
    return _build_self_signed(req, days, is_ca=True)


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_csr(data)
        return x509.load_der_x509_csr(data)
    except ValueError as exc:
        raise CsrError(_("Could not read the certificate request (CSR): {err}").format(err=exc)) from exc


def _ext_value(exts: x509.Extensions, cls):
    try:
        return exts.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _general_names_to_text(names) -> list[str]:
    out: list[str] = []
    for g in names:
        if isinstance(g, x509.IPAddress):
            out.append(str(g.value))
        elif isinstance(g, (x509.DNSName, x509.RFC822Name)):
            out.append(g.value)
        else:
            out.append(f"{type(g).__name__}:{g.value}")
    return out


def sign_csr(
    csr_data: bytes,
    ca_cert_data: bytes,
    ca_key_data: bytes,
    ca_key_password: str,
    days: int,
) -> SignedResult:
    """Sign a CSR with a local CA and return a TLS server certificate."""
    _check_days(days)
    csr = load_csr(csr_data)
    if not csr.is_signature_valid:
        raise CsrError(_("The signature on the CSR is invalid."))
    ca_key = load_key(ca_key_data, ca_key_password)
    ca_certs = _load_certs(ca_cert_data)
    ca = next((c for c in ca_certs if _same_public_key(c, ca_key)), None)
    if ca is None:
        raise CsrError(_("The CA certificate does not match the CA private key."))

    bc = _ext_value(ca.extensions, x509.BasicConstraints)
    if bc is None or not bc.ca:
        raise CsrError(_("The selected certificate is not a CA certificate."))
    ku = _ext_value(ca.extensions, x509.KeyUsage)
    if ku is not None and not ku.key_cert_sign:
        raise CsrError(_("The CA certificate is not allowed to sign certificates (keyCertSign)."))

    now = _utcnow()
    if ca.not_valid_after_utc < now:
        raise CsrError(_("The CA certificate has expired."))
    not_before = max(now - datetime.timedelta(minutes=5), ca.not_valid_before_utc)
    wanted_after = now + datetime.timedelta(days=days)
    not_after = min(wanted_after, ca.not_valid_after_utc)

    san_ext = _ext_value(csr.extensions, x509.SubjectAlternativeName)
    if san_ext is not None:
        san_names = list(san_ext)
    else:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        san_names = []
        if cn_attrs:
            try:
                san_names = [_san_to_general_name(str(cn_attrs[0].value))]
            except CsrError:
                pass

    pub = csr.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_leaf_key_usage(pub), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    )
    ca_ski = _ext_value(ca.extensions, x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)
        if ca_ski is not None
        else x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),
        critical=False,
    )
    if san_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)

    if _is_ed25519(ca_key):
        sign_hash = None
    else:
        try:
            sign_hash = ca.signature_hash_algorithm or hashes.SHA256()
        except Exception:
            sign_hash = hashes.SHA256()
    cert = builder.sign(ca_key, sign_hash)
    return SignedResult(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        subject=cert.subject.rfc4514_string(),
        sans=_general_names_to_text(san_names),
        not_after=not_after,
        clamped=not_after < wanted_after,
    )


# -------------------------------------------------------- key / files ----

def private_key_to_pem(key, password: str = "") -> bytes:
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


def write_private_file(path: str | os.PathLike, data: bytes) -> None:
    """Write a secret (private key / PFX). On POSIX the file is created with mode 0600.

    On Windows the folder's inherited permissions are kept on purpose, since keys are usually
    exported to be read by a service account (IIS, nginx, ...).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)  # also tighten a pre-existing file


def write_text_file(path: str | os.PathLike, text: str) -> None:
    Path(path).write_bytes(text.encode("ascii").replace(b"\r\n", b"\n"))


def load_key(data: bytes, password: str = "") -> PrivateKey:
    """Load a PEM/DER private key (RSA, ECDSA or Ed25519)."""
    pw = password.encode("utf-8") if password else None
    try:
        if b"-----BEGIN" in data:
            key = serialization.load_pem_private_key(data, pw)
        else:
            key = serialization.load_der_private_key(data, pw)
    except TypeError as exc:
        raise CsrError(_("The private key is encrypted - enter its password.")) from exc
    except ValueError as exc:
        raise CsrError(
            _("Could not read the private key. Is the password correct and the format PEM/DER?")
        ) from exc
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        raise CsrError(_("Unsupported private key type (RSA, ECDSA and Ed25519 are supported)."))
    return key


# ---------------------------------------------------------------- PFX ----

def _load_certs(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN" in data:
        try:
            if b"BEGIN PKCS7" in data:
                from cryptography.hazmat.primitives.serialization import pkcs7

                return pkcs7.load_pem_pkcs7_certificates(data)
            return x509.load_pem_x509_certificates(data)
        except ValueError as exc:
            raise CsrError(_("Could not read certificate (PEM): {err}").format(err=exc)) from exc
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        pass
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        return pkcs7.load_der_pkcs7_certificates(data)
    except Exception as exc:
        raise CsrError(
            _("Could not read the certificate file (supported formats: PEM, DER and P7B).")
        ) from exc


def _same_public_key(cert: x509.Certificate, key) -> bool:
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_key().public_bytes(*fmt) == key.public_key().public_bytes(*fmt)


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def _is_self_signed(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer and _issued_by(cert, cert)


def _name_of(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string() or "(empty)"


def export_warnings(
    leaf: x509.Certificate, chain: list[x509.Certificate], now: datetime.datetime | None = None
) -> list[str]:
    """Return human-readable problems worth confirming before exporting."""
    now = now or _utcnow()
    warnings: list[str] = []
    for cert in [leaf] + chain:
        label = _name_of(cert)
        if cert.not_valid_after_utc < now:
            warnings.append(_("Certificate has EXPIRED ({date}): {subject}").format(
                date=f"{cert.not_valid_after_utc:%Y-%m-%d}", subject=label))
        elif cert.not_valid_before_utc > now:
            warnings.append(_("Certificate is not valid yet (starts {date}): {subject}").format(
                date=f"{cert.not_valid_before_utc:%Y-%m-%d}", subject=label))
        elif (cert.not_valid_after_utc - now).days < EXPIRY_WARNING_DAYS:
            warnings.append(_("Certificate expires in {days} days: {subject}").format(
                days=(cert.not_valid_after_utc - now).days, subject=label))
    if _ext_value(leaf.extensions, x509.SubjectAlternativeName) is None:
        warnings.append(_("The certificate has no Subject Alternative Name (modern browsers require one)."))
    if not _is_self_signed(leaf) and not any(_issued_by(leaf, c) for c in chain):
        warnings.append(_(
            "The issuing (intermediate) certificate was not found. Clients may not be able to build "
            "the trust chain - add the intermediate certificates from your CA."
        ))
    return warnings


def fetch_missing_issuers(
    leaf: x509.Certificate,
    chain: list[x509.Certificate],
    timeout: float = 10.0,
    max_depth: int = 5,
) -> tuple[list[x509.Certificate], list[str]]:
    """Download missing intermediates via the AIA 'CA Issuers' extension (http/https only).

    Returns (new certificates, status messages). This is the only code that uses the network and
    it only runs when the user opts in.
    """
    import urllib.request

    pool = list(chain)
    found: list[x509.Certificate] = []
    notes: list[str] = []
    current = leaf
    for _depth in range(max_depth):
        if _is_self_signed(current):
            break
        issuer = next((c for c in pool if _issued_by(current, c)), None)
        if issuer is not None:
            current = issuer
            continue
        aia = _ext_value(current.extensions, x509.AuthorityInformationAccess)
        urls = [
            d.access_location.value
            for d in (aia or [])
            if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
            and d.access_location.value.lower().startswith(("http://", "https://"))
        ]
        got = None
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CertificateTool"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
                    data = resp.read(1_000_001)
                if len(data) > 1_000_000:
                    raise CsrError("response too large")
                got = next((c for c in _load_certs(data) if _issued_by(current, c)), None)
            except Exception as exc:
                notes.append(_("Could not download {url}: {err}").format(url=url, err=exc))
                continue
            if got is not None:
                notes.append(_("Downloaded intermediate certificate: {subject}").format(subject=_name_of(got)))
                break
        if got is None:
            break
        pool.append(got)
        found.append(got)
        current = got
    return found, notes


def prepare_export(
    cert_data: bytes,
    key_data: bytes,
    key_password: str,
    chain_data: bytes | None,
    fetch_aia: bool = False,
) -> ExportBundle:
    """Load certificate, key and chain, check they belong together and collect warnings."""
    certs = _load_certs(cert_data)
    key = load_key(key_data, key_password)

    leaf = next((c for c in certs if _same_public_key(c, key)), None)
    if leaf is None:
        raise CsrError(_("The certificate does not match the private key."))

    chain = [c for c in certs if c is not leaf]
    if chain_data:
        for c in _load_certs(chain_data):
            if c != leaf and c not in chain:
                chain.append(c)
    notes: list[str] = []
    if fetch_aia:
        extra, notes = fetch_missing_issuers(leaf, chain)
        chain.extend(extra)
    return ExportBundle(leaf, chain, key, export_warnings(leaf, chain), notes)


def _certs_to_pem(certs: list[x509.Certificate]) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def certificates_to_pem(cert_data: bytes) -> bytes:
    """Normalise certificates in any supported format (PEM/DER/P7B) to concatenated PEM."""
    return _certs_to_pem(_load_certs(cert_data))


def pem_files(bundle: ExportBundle, out_key_password: str = "") -> dict[str, bytes]:
    """PEM files. Keys: 'crt', 'key' and (if a chain exists) 'chain', 'fullchain'.

    The key is unencrypted if out_key_password is empty (typically required by nginx/Apache).
    """
    files = {
        "crt": _certs_to_pem([bundle.leaf]),
        "key": private_key_to_pem(bundle.key, out_key_password),
    }
    if bundle.chain:
        files["chain"] = _certs_to_pem(bundle.chain)
        files["fullchain"] = _certs_to_pem([bundle.leaf] + bundle.chain)
    return files


def pfx_bytes(
    bundle: ExportBundle,
    pfx_password: str,
    friendly_name: str = "",
    legacy_encryption: bool = False,
) -> bytes:
    if pfx_password:
        if legacy_encryption:
            enc = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .kdf_rounds(2048)
                .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .hmac_hash(hashes.SHA1())
                .build(pfx_password.encode("utf-8"))
            )
        else:
            enc = serialization.BestAvailableEncryption(pfx_password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()

    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8") if friendly_name else None,
        key=bundle.key,
        cert=bundle.leaf,
        cas=bundle.chain or None,
        encryption_algorithm=enc,
    )


def build_pem_files(
    cert_data: bytes,
    key_data: bytes,
    key_password: str,
    chain_data: bytes | None,
    out_key_password: str = "",
) -> dict[str, bytes]:
    return pem_files(prepare_export(cert_data, key_data, key_password, chain_data), out_key_password)


def build_pfx(
    cert_data: bytes,
    key_data: bytes,
    key_password: str,
    chain_data: bytes | None,
    pfx_password: str,
    friendly_name: str = "",
    legacy_encryption: bool = False,
) -> bytes:
    bundle = prepare_export(cert_data, key_data, key_password, chain_data)
    return pfx_bytes(bundle, pfx_password, friendly_name, legacy_encryption)


def bundle_from_pfx(data: bytes, password: str = "") -> ExportBundle:
    """Open a PFX/P12 file (for converting it to PEM files)."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8") if password else None
        )
    except (ValueError, TypeError) as exc:
        raise CsrError(_("Could not open the PFX file. Is the password correct?")) from exc
    except Exception as exc:  # e.g. UnsupportedAlgorithm for very old encryption
        raise CsrError(_("Could not open the PFX file: {err}").format(err=exc)) from exc
    if key is None or cert is None:
        raise CsrError(_("The PFX file does not contain both a certificate and a private key."))
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)):
        raise CsrError(_("Unsupported private key type (RSA, ECDSA and Ed25519 are supported)."))
    chain = list(extra or [])
    return ExportBundle(cert, chain, key, export_warnings(cert, chain))


# --------------------------------------------------------- inspection ----

def _fingerprint(cert_or_csr, algo) -> str:
    digest = cert_or_csr.fingerprint(algo)
    return ":".join(f"{b:02X}" for b in digest)


_KU_NAMES = [
    "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
    "key_agreement", "key_cert_sign", "crl_sign",
]


def _signature_name(obj) -> str:
    oid = obj.signature_algorithm_oid
    return getattr(oid, "_name", oid.dotted_string)


def describe_certificate(cert: x509.Certificate, now: datetime.datetime | None = None) -> str:
    now = now or _utcnow()
    na, nb = cert.not_valid_after_utc, cert.not_valid_before_utc
    if na < now:
        status = _("EXPIRED")
    elif nb > now:
        status = _("not valid yet")
    else:
        status = _("valid, {days} days left").format(days=(na - now).days)
    lines = [
        _("Subject:") + f" {cert.subject.rfc4514_string()}",
        _("Issuer:") + f" {cert.issuer.rfc4514_string()}",
        _("Self-signed:") + " " + (_("yes") if _is_self_signed(cert) else _("no")),
        _("Serial number:") + f" {cert.serial_number:X}",
        _("Valid from:") + f" {nb:%Y-%m-%d %H:%M} UTC",
        _("Valid until:") + f" {na:%Y-%m-%d %H:%M} UTC ({status})",
        _("Key:") + f" {key_description(cert.public_key())}",
        _("Signature algorithm:") + f" {_signature_name(cert)}",
    ]
    sans = _ext_value(cert.extensions, x509.SubjectAlternativeName)
    lines.append(_("Subject Alternative Names:") + " " + (", ".join(_general_names_to_text(sans)) if sans else _("none")))
    bc = _ext_value(cert.extensions, x509.BasicConstraints)
    if bc is not None:
        lines.append(_("CA certificate:") + " " + (_("yes") if bc.ca else _("no")))
    ku = _ext_value(cert.extensions, x509.KeyUsage)
    if ku is not None:
        used = [n for n in _KU_NAMES if getattr(ku, n)]
        lines.append(_("Key usage:") + " " + ", ".join(used))
    eku = _ext_value(cert.extensions, x509.ExtendedKeyUsage)
    if eku is not None:
        lines.append(_("Extended key usage:") + " " + ", ".join(getattr(o, "_name", o.dotted_string) for o in eku))
    lines.append("SHA-256: " + _fingerprint(cert, hashes.SHA256()))
    lines.append("SHA-1: " + _fingerprint(cert, hashes.SHA1()))
    return "\n".join(lines)


def describe_csr(csr: x509.CertificateSigningRequest) -> str:
    lines = [
        _("Subject:") + f" {csr.subject.rfc4514_string()}",
        _("Key:") + f" {key_description(csr.public_key())}",
        _("Signature algorithm:") + f" {_signature_name(csr)}",
        _("Signature valid:") + " " + (_("yes") if csr.is_signature_valid else _("NO")),
    ]
    sans = _ext_value(csr.extensions, x509.SubjectAlternativeName)
    lines.append(_("Subject Alternative Names:") + " " + (", ".join(_general_names_to_text(sans)) if sans else _("none")))
    return "\n".join(lines)


def inspect_data(data: bytes) -> str:
    """Describe a certificate (PEM/DER/P7B, possibly several) or a CSR."""
    if b"CERTIFICATE REQUEST" in data:
        return _("Certificate request (CSR)") + "\n" + describe_csr(load_csr(data))
    try:
        certs = _load_certs(data)
    except CsrError:
        try:
            return _("Certificate request (CSR)") + "\n" + describe_csr(load_csr(data))
        except CsrError:
            raise CsrError(
                _("Could not read the data as a certificate or CSR (PEM, DER or P7B).")
            ) from None
    if not certs:
        raise CsrError(_("No certificates found."))
    blocks = []
    for i, cert in enumerate(certs, 1):
        head = _("Certificate {n} of {total}").format(n=i, total=len(certs))
        blocks.append(f"{head}\n{describe_certificate(cert)}")
    return "\n\n".join(blocks)
