"""AIA download of missing intermediates, against a throw-away local HTTP server."""

import datetime
import http.server
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

import csrgen


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer_cert, issuer_key, key, ca, aia_url=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(subject))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aia_url:
        b = b.add_extension(
            x509.AuthorityInformationAccess(
                [x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia_url))]
            ),
            critical=False,
        )
    return b.sign(issuer_key, hashes.SHA256())


@pytest.fixture()
def pki():
    root_key, inter_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Root", None, root_key, root_key, True)
    inter = _cert("Intermediate", root, root_key, inter_key, True)
    served = inter.public_bytes(serialization.Encoding.DER)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(served)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/inter.cer"
    leaf = _cert("leaf.example.com", inter, inter_key, leaf_key, False, aia_url=url)
    yield dict(leaf=leaf, leaf_key=leaf_key, inter=inter, root=root)
    server.shutdown()


def test_fetches_missing_intermediate(pki):
    found, notes = csrgen.fetch_missing_issuers(pki["leaf"], [])
    assert [c.subject for c in found] == [pki["inter"].subject]
    assert any("Downloaded" in n for n in notes)


def test_prepare_export_with_aia(pki):
    cert = pki["leaf"].public_bytes(serialization.Encoding.PEM)
    key = csrgen.private_key_to_pem(pki["leaf_key"])
    without = csrgen.prepare_export(cert, key, "", None)
    assert any("intermediate" in w for w in without.warnings)
    with_aia = csrgen.prepare_export(cert, key, "", None, fetch_aia=True)
    assert len(with_aia.chain) == 1
    assert not any("intermediate" in w for w in with_aia.warnings)


def test_nothing_to_fetch_for_self_signed_or_complete_chain(pki):
    assert csrgen.fetch_missing_issuers(pki["root"], []) == ([], [])
    found, _notes = csrgen.fetch_missing_issuers(pki["leaf"], [pki["inter"]])
    assert found == []


def test_non_http_urls_are_ignored():
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer = _cert("I", None, issuer_key, issuer_key, True)
    leaf = _cert("l.example.com", issuer, issuer_key, key, False, aia_url="file:///etc/passwd")
    found, notes = csrgen.fetch_missing_issuers(leaf, [])
    assert found == [] and notes == []


def test_unreachable_server_is_reported_not_raised():
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer = _cert("I", None, issuer_key, issuer_key, True)
    leaf = _cert("l.example.com", issuer, issuer_key, key, False, aia_url="http://127.0.0.1:9/x.cer")
    found, notes = csrgen.fetch_missing_issuers(leaf, [], timeout=2)
    assert found == [] and len(notes) == 1 and "Could not download" in notes[0]
