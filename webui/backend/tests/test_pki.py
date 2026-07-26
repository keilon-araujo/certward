"""Testes da lib pura de PKI (sem HTTP, sem openssl)."""
import datetime
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import pki
from pki import EngineError


def _make_cert(cn="app.test.lab", server=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    now = datetime.datetime.now(datetime.timezone.utc)
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    return (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(0x1000)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            .sign(key, hashes.SHA256()))


def test_fname_wildcard():
    assert pki.fname("*.capsule.lab.br") == "wildcard.capsule.lab.br"
    assert pki.fname("app1.capsule.lab.br") == "app1.capsule.lab.br"


def test_random_pw_length_and_charset():
    pw = pki.random_pw(30)
    assert len(pw) == 30
    assert all(c.isprintable() and not c.isspace() for c in pw)


@pytest.mark.parametrize("name,ok", [
    ("app1.capsule.lab.br", True), ("*.capsule.lab.br", True),
    ("a_b-c.d", True), ("bad name", False), ("a/b", False), ("*.*.x", False),
])
def test_wildcard_re(name, ok):
    assert bool(pki.WILDCARD_RE.match(name)) is ok


@pytest.mark.parametrize("dom,ok", [
    ("capsule.lab.br", True), ("acme.lab.local", True), ("a.io", True),
    ("nodot", False), ("bad_domain", False), ("UPPER.com", False),
])
def test_domain_re(dom, ok):
    assert bool(pki.DOMAIN_RE.match(dom)) is ok


def test_decode_cert_fields():
    cert = _make_cert()
    dec = pki.decode_cert(cert)
    assert dec["version"] == "v3"
    assert dec["self_signed"] is True
    assert any(p["attr"] == "CN" and p["value"] == "app.test.lab" for p in dec["subject"])
    names = [e for e in dec["extensions"] if e["name"] == "subjectAltName"]
    assert names and "DNS:app.test.lab" in names[0]["value"]
    assert "sha256" in dec["fingerprints"] and ":" in dec["fingerprints"]["sha256"]


def test_cert_helpers():
    cert = _make_cert(server=True)
    assert pki.common_name(cert) == "app.test.lab"
    assert pki.profile_of(cert) == "server"
    assert pki.san_list(cert) == ["DNS:app.test.lab"]
    assert pki.profile_of(_make_cert(server=False)) == "client"


def _cfg(**over):
    base = dict(domain="capsule.lab.br", org="Capsule Corp", ou=None, country="BR",
                state="", locality="", root_cn=None, intermediate_cn=None,
                ca_host=None, ocsp_host=None, admin_host=None,
                key_size=4096, leaf_key_size=2048, root_days=3650, intermediate_days=1825,
                leaf_days=375, crl_days=30, crl_days_root=180, digest="sha256",
                passphrase="uma-senha-forte")
    base.update(over)
    return types.SimpleNamespace(**base)


def test_resolve_config_defaults():
    cfg = pki.resolve_config(_cfg())
    assert cfg["domain"] == "capsule.lab.br"
    assert cfg["ou"] == "Capsule Corp CA"
    assert cfg["root_cn"] == "Capsule Corp Root CA"
    assert cfg["ca_host"] == "ca.capsule.lab.br"
    assert cfg["ocsp_host"] == "ocsp.capsule.lab.br"
    assert cfg["admin_host"] == "admin.capsule.lab.br"


@pytest.mark.parametrize("over,msg", [
    (dict(domain="semponto"), "dominio"),
    (dict(org=""), "organizacao"),
    (dict(country="BRA"), "pais"),
    (dict(passphrase="curta"), "passphrase"),
    (dict(digest="md5"), "digest"),
    (dict(key_size=1024), "chave"),
])
def test_resolve_config_invalid(over, msg):
    with pytest.raises(EngineError) as ei:
        pki.resolve_config(_cfg(**over))
    assert ei.value.status == 400
    assert msg in ei.value.detail


def test_decode_pem_invalid():
    with pytest.raises(EngineError):
        pki.decode_pem("nao e um pem")
