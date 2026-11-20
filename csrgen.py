"""Logic for generating CSRs and building PFX/PEM files. No GUI code here."""

from __future__ import annotations

import datetime
import ipaddress
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RSA_SIZES = ["2048", "3072", "4096"]
EC_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
HASHES = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
}
KEY_ALGORITHMS = ["RSA", "ECDSA"]

# Max lengths per RFC 5280 (upper bounds) - the same limits IIS and CAs enforce
MAX_LEN = {"CN": 64, "O": 64, "OU": 64, "L": 128, "ST": 128}


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
    key_size: str = "2048"  # RSA: bit length, ECDSA: curve name
    hash_name: str = "SHA-256"
    san_entries: list[str] = field(default_factory=list)
    include_cn_in_san: bool = True


@dataclass
class CsrResult:
    csr_pem: str
    private_key: object
    subject: str
    sans: list[str]


def parse_san_text(text: str) -> list[str]:
    """Split text into SAN entries (newline, comma, semicolon or whitespace)."""
    parts = re.split(r"[\s,;]+", text.strip())
    out: list[str] = []
    for p in parts:
        if p and p not in out:
            out.append(p)
    return out


def _san_to_general_name(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "@" in value:
        return x509.RFC822Name(value)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CsrError(f"Invalid domain name in SAN: {value}") from exc
    if not re.fullmatch(r"(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*", value):
        raise CsrError(f"Invalid domain name in SAN: {value}")
    return x509.DNSName(value)


def validate(req: CsrRequest) -> None:
    if not req.common_name.strip():
        raise CsrError("Common name is required.")
    values = {
        "CN": req.common_name,
        "O": req.organization,
        "OU": req.organizational_unit,
        "L": req.locality,
        "ST": req.state,
    }
    for key, val in values.items():
        if len(val.strip()) > MAX_LEN[key]:
            raise CsrError(f"{key} must be at most {MAX_LEN[key]} characters.")
    if req.country and not re.fullmatch(r"[A-Za-z]{2}", req.country.strip()):
        raise CsrError("Country/region must be a 2-letter country code (e.g. DK).")
    for key, val in values.items():
        if "\n" in val or "\r" in val:
            raise CsrError(f"{key} must not contain line breaks.")
    if req.key_algorithm == "RSA":
        if req.key_size not in RSA_SIZES:
            raise CsrError("Invalid RSA bit length.")
    elif req.key_algorithm == "ECDSA":
        if req.key_size not in EC_CURVES:
            raise CsrError("Invalid ECDSA curve.")
    else:
        raise CsrError("Unknown key algorithm.")
    if req.hash_name not in HASHES:
        raise CsrError("Invalid hash algorithm.")


def _generate_key(req: CsrRequest):
    if req.key_algorithm == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(req.key_size))
    return ec.generate_private_key(EC_CURVES[req.key_size]())


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
    csr = builder.sign(key, HASHES[req.hash_name]())
    if not csr.is_signature_valid:  # pragma: no cover - sanity check
        raise CsrError("Internal error: the CSR signature is invalid.")

    return CsrResult(
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        subject=csr.subject.rfc4514_string(),
        sans=sans,
    )


@dataclass
class SelfSignedResult:
    cert_pem: str
    private_key: object
    subject: str
    sans: list[str]
    not_after: datetime.datetime


MAX_VALIDITY_DAYS = 36500


def generate_self_signed(req: CsrRequest, days: int) -> SelfSignedResult:
    """Create a self-signed TLS server certificate (subject == issuer)."""
    validate(req)
    if not 1 <= days <= MAX_VALIDITY_DAYS:
        raise CsrError(f"Validity must be between 1 and {MAX_VALIDITY_DAYS} days.")
    name = _build_name(req)
    sans = _collect_sans(req)
    key = _generate_key(req)

    now = datetime.datetime.now(datetime.timezone.utc)
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
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=req.key_algorithm == "RSA",
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san_to_general_name(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, HASHES[req.hash_name]())
    return SelfSignedResult(
        cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        private_key=key,
        subject=cert.subject.rfc4514_string(),
        sans=sans,
        not_after=not_after,
    )


def private_key_to_pem(key, password: str = "") -> bytes:
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


# ---------------------------------------------------------------- PFX ----

def _load_certs(data: bytes) -> list[x509.Certificate]:
    if b"-----BEGIN" in data:
        try:
            if b"BEGIN PKCS7" in data:
                from cryptography.hazmat.primitives.serialization import pkcs7

                return pkcs7.load_pem_pkcs7_certificates(data)
            return x509.load_pem_x509_certificates(data)
        except ValueError as exc:
            raise CsrError(f"Could not read certificate (PEM): {exc}") from exc
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        pass
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        return pkcs7.load_der_pkcs7_certificates(data)
    except Exception as exc:
        raise CsrError("Could not read the certificate file (supported formats: PEM, DER and P7B).") from exc


def _load_key(data: bytes, password: str):
    pw = password.encode("utf-8") if password else None
    try:
        if b"-----BEGIN" in data:
            return serialization.load_pem_private_key(data, pw)
        return serialization.load_der_private_key(data, pw)
    except TypeError as exc:
        raise CsrError("The private key is encrypted - enter its password.") from exc
    except ValueError as exc:
        raise CsrError(
            "Could not read the private key. Is the password correct and the format PEM/DER?"
        ) from exc


def _same_public_key(cert: x509.Certificate, key) -> bool:
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_key().public_bytes(*fmt) == key.public_key().public_bytes(*fmt)


def _prepare(
    cert_data: bytes, key_data: bytes, key_password: str, chain_data: bytes | None
):
    """Load certificate, key and chain. Returns (leaf, chain, key)."""
    certs = _load_certs(cert_data)
    key = _load_key(key_data, key_password)

    leaf = next((c for c in certs if _same_public_key(c, key)), None)
    if leaf is None:
        raise CsrError("The certificate does not match the private key.")

    chain = [c for c in certs if c is not leaf]
    if chain_data:
        for c in _load_certs(chain_data):
            if c != leaf and c not in chain:
                chain.append(c)
    return leaf, chain, key


def _certs_to_pem(certs: list[x509.Certificate]) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def build_pem_files(
    cert_data: bytes,
    key_data: bytes,
    key_password: str,
    chain_data: bytes | None,
    out_key_password: str = "",
) -> dict[str, bytes]:
    """Build PEM files. Result keys: 'crt', 'key' and (if a chain exists) 'chain', 'fullchain'.

    The key is unencrypted if out_key_password is empty (typically required by nginx/Apache).
    """
    leaf, chain, key = _prepare(cert_data, key_data, key_password, chain_data)
    files = {
        "crt": _certs_to_pem([leaf]),
        "key": private_key_to_pem(key, out_key_password),
    }
    if chain:
        files["chain"] = _certs_to_pem(chain)
        files["fullchain"] = _certs_to_pem([leaf] + chain)
    return files


def build_pfx(
    cert_data: bytes,
    key_data: bytes,
    key_password: str,
    chain_data: bytes | None,
    pfx_password: str,
    friendly_name: str = "",
    legacy_encryption: bool = False,
) -> bytes:
    leaf, chain, key = _prepare(cert_data, key_data, key_password, chain_data)

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
        key=key,
        cert=leaf,
        cas=chain or None,
        encryption_algorithm=enc,
    )
