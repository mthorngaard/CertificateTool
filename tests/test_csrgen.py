import datetime
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import csrgen
from csrgen import CsrError, CsrRequest


def req(**kw) -> CsrRequest:
    base = dict(common_name="www.example.com", organization="Example A/S", country="DK")
    base.update(kw)
    return CsrRequest(**base)


# ------------------------------------------------------------ SAN ----

def test_parse_san_text_splits_and_dedupes():
    assert csrgen.parse_san_text("a.com, b.com;a.com\n c.com") == ["a.com", "b.com", "c.com"]
    assert csrgen.parse_san_text("   ") == []


@pytest.mark.parametrize("value", ["bad host", "-x.com", "a..b.com", "a b"])
def test_invalid_san_rejected(value):
    with pytest.raises(CsrError):
        csrgen._san_to_general_name(value)


def test_san_types():
    assert isinstance(csrgen._san_to_general_name("10.0.0.1"), x509.IPAddress)
    assert isinstance(csrgen._san_to_general_name("::1"), x509.IPAddress)
    assert isinstance(csrgen._san_to_general_name("a@b.dk"), x509.RFC822Name)
    assert isinstance(csrgen._san_to_general_name("*.example.com"), x509.DNSName)
    idn = csrgen._san_to_general_name("bl\u00e5b\u00e6r.dk")
    assert idn.value == "xn--blb-1ka6e.dk" or idn.value.startswith("xn--")


# ------------------------------------------------------------ CSR ----

@pytest.mark.parametrize(
    "alg,size",
    [("RSA", "2048"), ("ECDSA", "P-256"), ("ECDSA", "P-384"), ("Ed25519", "")],
)
def test_csr_roundtrip(alg, size):
    res = csrgen.generate_csr(req(key_algorithm=alg, key_size=size, san_entries=["alt.example.com"]))
    csr = x509.load_pem_x509_csr(res.csr_pem.encode())
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "www.example.com"
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["www.example.com", "alt.example.com"]
    assert res.sans == ["www.example.com", "alt.example.com"]
    assert not res.reused_key


def test_csr_cn_not_hostname_is_not_san():
    res = csrgen.generate_csr(req(common_name="My Company Name"))
    assert res.sans == []


def test_csr_reuses_existing_key():
    key = ec.generate_private_key(ec.SECP256R1())
    res = csrgen.generate_csr(req(existing_key=key))
    assert res.private_key is key and res.reused_key
    csr = x509.load_pem_x509_csr(res.csr_pem.encode())
    assert csr.public_key().public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize(
    "kw",
    [
        dict(common_name=" "),
        dict(common_name="x" * 65),
        dict(country="DNK"),
        dict(key_size="1024"),
        dict(key_algorithm="ECDSA", key_size="2048"),
        dict(key_algorithm="DSA"),
        dict(hash_name="MD5"),
        dict(organization="a\nb"),
    ],
)
def test_validation_errors(kw):
    with pytest.raises(CsrError):
        csrgen.generate_csr(req(**kw))


# ----------------------------------------------------- self-signed ----

@pytest.mark.parametrize("alg,size", [("RSA", "2048"), ("ECDSA", "P-256"), ("Ed25519", "")])
def test_self_signed(alg, size):
    res = csrgen.generate_self_signed(req(key_algorithm=alg, key_size=size), 30)
    cert = x509.load_pem_x509_certificate(res.cert_pem.encode())
    assert cert.subject == cert.issuer
    assert csrgen._is_self_signed(cert)
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_encipherment == (alg == "RSA")
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    assert days == 30


@pytest.mark.parametrize("days", [0, -1, csrgen.MAX_VALIDITY_DAYS + 1])
def test_self_signed_validity_bounds(days):
    with pytest.raises(CsrError):
        csrgen.generate_self_signed(req(), days)


# --------------------------------------------------------- local CA ----

def make_ca(**kw):
    return csrgen.generate_ca(req(common_name="Test Root CA", key_algorithm="ECDSA", key_size="P-256", **kw), 365)


def test_ca_certificate_properties():
    ca = make_ca()
    cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert ca.sans == []


def test_sign_csr_chain_validates():
    ca = make_ca()
    csr = csrgen.generate_csr(req(san_entries=["alt.example.com", "10.1.2.3"]))
    signed = csrgen.sign_csr(
        csr.csr_pem.encode(), ca.cert_pem.encode(), csrgen.private_key_to_pem(ca.private_key), "", 90
    )
    leaf = x509.load_pem_x509_certificate(signed.cert_pem.encode())
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    leaf.verify_directly_issued_by(ca_cert)
    assert leaf.issuer == ca_cert.subject
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert signed.sans == ["www.example.com", "alt.example.com", "10.1.2.3"]
    assert not signed.clamped
    assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days in (90, 89)


def test_sign_csr_clamped_to_ca_expiry():
    ca = csrgen.generate_ca(req(common_name="Short CA"), 10)
    csr = csrgen.generate_csr(req())
    signed = csrgen.sign_csr(
        csr.csr_pem.encode(), ca.cert_pem.encode(), csrgen.private_key_to_pem(ca.private_key), "", 365
    )
    assert signed.clamped
    assert signed.not_after <= ca.not_after + datetime.timedelta(seconds=1)


def test_sign_csr_rejects_non_ca_and_wrong_key():
    leaf_like = csrgen.generate_self_signed(req(), 30)
    csr = csrgen.generate_csr(req())
    with pytest.raises(CsrError, match="not a CA"):
        csrgen.sign_csr(
            csr.csr_pem.encode(), leaf_like.cert_pem.encode(),
            csrgen.private_key_to_pem(leaf_like.private_key), "", 30,
        )
    ca = make_ca()
    other = csrgen.generate_ca(req(common_name="Other CA"), 30)
    with pytest.raises(CsrError, match="does not match"):
        csrgen.sign_csr(
            csr.csr_pem.encode(), ca.cert_pem.encode(),
            csrgen.private_key_to_pem(other.private_key), "", 30,
        )


def test_sign_csr_ed25519_ca():
    ca = csrgen.generate_ca(req(common_name="Ed CA", key_algorithm="Ed25519"), 30)
    csr = csrgen.generate_csr(req())
    signed = csrgen.sign_csr(
        csr.csr_pem.encode(), ca.cert_pem.encode(), csrgen.private_key_to_pem(ca.private_key), "", 30
    )
    leaf = x509.load_pem_x509_certificate(signed.cert_pem.encode())
    leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.cert_pem.encode()))


# ------------------------------------------------------ export / PFX ----

@pytest.fixture()
def issued():
    """A CA-issued leaf plus its key, CA cert and a P7B-less setup."""
    ca = make_ca()
    csr = csrgen.generate_csr(req())
    signed = csrgen.sign_csr(
        csr.csr_pem.encode(), ca.cert_pem.encode(), csrgen.private_key_to_pem(ca.private_key), "", 90
    )
    return dict(
        cert=signed.cert_pem.encode(),
        key=csrgen.private_key_to_pem(csr.private_key, "keypw"),
        chain=ca.cert_pem.encode(),
    )


def test_pem_export_with_chain(issued):
    files = csrgen.build_pem_files(issued["cert"], issued["key"], "keypw", issued["chain"], "")
    assert set(files) == {"crt", "key", "chain", "fullchain"}
    assert b"ENCRYPTED" not in files["key"]
    assert files["fullchain"].count(b"BEGIN CERTIFICATE") == 2
    encrypted = csrgen.build_pem_files(issued["cert"], issued["key"], "keypw", None, "new")
    assert b"ENCRYPTED" in encrypted["key"] and set(encrypted) == {"crt", "key"}


def test_pfx_roundtrip_and_legacy(issued):
    for legacy in (False, True):
        pfx = csrgen.build_pfx(issued["cert"], issued["key"], "keypw", issued["chain"], "pw", "friendly", legacy)
        key, cert, extra = pkcs12.load_key_and_certificates(pfx, b"pw")
        assert cert is not None and key is not None and len(extra) == 1


def test_wrong_key_password_and_mismatch(issued):
    with pytest.raises(CsrError):
        csrgen.build_pem_files(issued["cert"], issued["key"], "wrong", None)
    with pytest.raises(CsrError, match="encrypted"):
        csrgen.build_pem_files(issued["cert"], issued["key"], "", None)
    other = csrgen.private_key_to_pem(ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(CsrError, match="does not match"):
        csrgen.build_pem_files(issued["cert"], other, "", None)


def test_der_and_p7b_inputs(issued):
    leaf = x509.load_pem_x509_certificate(issued["cert"])
    ca = x509.load_pem_x509_certificate(issued["chain"])
    der = leaf.public_bytes(serialization.Encoding.DER)
    files = csrgen.build_pem_files(der, issued["key"], "keypw", None)
    assert b"BEGIN CERTIFICATE" in files["crt"]

    from cryptography.hazmat.primitives.serialization import pkcs7

    p7_pem = pkcs7.serialize_certificates([leaf, ca], serialization.Encoding.PEM)
    p7_der = pkcs7.serialize_certificates([leaf, ca], serialization.Encoding.DER)
    for p7 in (p7_pem, p7_der):
        files = csrgen.build_pem_files(p7, issued["key"], "keypw", None)
        assert "chain" in files  # CA taken from the bundle


def test_pfx_to_pem_conversion(issued):
    pfx = csrgen.build_pfx(issued["cert"], issued["key"], "keypw", issued["chain"], "pw")
    bundle = csrgen.bundle_from_pfx(pfx, "pw")
    files = csrgen.pem_files(bundle, "")
    assert set(files) == {"crt", "key", "chain", "fullchain"}
    with pytest.raises(CsrError):
        csrgen.bundle_from_pfx(pfx, "wrong")
    with pytest.raises(CsrError):
        csrgen.bundle_from_pfx(b"not a pfx", "x")


def test_export_warnings(issued):
    bundle = csrgen.prepare_export(issued["cert"], issued["key"], "keypw", issued["chain"])
    assert bundle.warnings == []
    no_chain = csrgen.prepare_export(issued["cert"], issued["key"], "keypw", None)
    assert any("intermediate" in w for w in no_chain.warnings)
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=4000)
    assert any("EXPIRED" in w for w in csrgen.export_warnings(bundle.leaf, bundle.chain, future))
    soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=80)
    assert any("expires in" in w for w in csrgen.export_warnings(bundle.leaf, bundle.chain, soon))


def test_self_signed_has_no_chain_warning():
    res = csrgen.generate_self_signed(req(), 365)
    bundle = csrgen.prepare_export(
        res.cert_pem.encode(), csrgen.private_key_to_pem(res.private_key), "", None
    )
    assert bundle.warnings == []


def test_ed25519_pfx():
    res = csrgen.generate_self_signed(req(key_algorithm="Ed25519"), 30)
    pfx = csrgen.build_pfx(res.cert_pem.encode(), csrgen.private_key_to_pem(res.private_key), "", None, "pw")
    key, cert, _extra = pkcs12.load_key_and_certificates(pfx, b"pw")
    assert isinstance(key, ed25519.Ed25519PrivateKey)


def test_load_key_variants():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    assert isinstance(csrgen.load_key(der), rsa.RSAPrivateKey)
    with pytest.raises(CsrError):
        csrgen.load_key(b"garbage")


# -------------------------------------------------------- inspect ----

def test_inspect_certificate_and_csr(issued):
    text = csrgen.inspect_data(issued["cert"] + issued["chain"])
    assert "Certificate 1 of 2" in text and "Certificate 2 of 2" in text
    assert "www.example.com" in text and "SHA-256:" in text
    assert "CA certificate: yes" in text

    csr = csrgen.generate_csr(req(san_entries=["alt.example.com"]))
    out = csrgen.inspect_data(csr.csr_pem.encode())
    assert "CSR" in out and "alt.example.com" in out and "Signature valid: yes" in out

    der = x509.load_pem_x509_certificate(issued["cert"]).public_bytes(serialization.Encoding.DER)
    assert "www.example.com" in csrgen.inspect_data(der)

    with pytest.raises(CsrError):
        csrgen.inspect_data(b"nonsense")


# ---------------------------------------------------- file writing ----

def test_write_private_file(tmp_path):
    p = tmp_path / "k.key"
    csrgen.write_private_file(p, b"secret")
    assert p.read_bytes() == b"secret"
    csrgen.write_private_file(p, b"x")  # overwrite truncates
    assert p.read_bytes() == b"x"
    if os.name != "nt":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_write_private_file_tightens_existing(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permissions only")
    p = tmp_path / "k.key"
    p.write_bytes(b"old")
    p.chmod(0o644)
    csrgen.write_private_file(p, b"new")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_write_text_file_uses_lf(tmp_path):
    p = tmp_path / "a.csr"
    csrgen.write_text_file(p, "a\r\nb\n")
    assert p.read_bytes() == b"a\nb\n"


def test_key_description():
    assert csrgen.key_description(ec.generate_private_key(ec.SECP384R1())).startswith("ECDSA")
    assert csrgen.key_description(ed25519.Ed25519PrivateKey.generate()) == "Ed25519"
