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


# --------------------------------------------------------------- name constraints
def test_resolve_config_name_constraints_default_on():
    assert pki.resolve_config(_cfg())["name_constraints"] is True
    assert pki.resolve_config(_cfg(name_constraints=False))["name_constraints"] is False


def test_name_constraints_line():
    on = pki._name_constraints_line({"domain": "capsule.lab.br", "name_constraints": True})
    assert "critical" in on
    assert "permitted;DNS:capsule.lab.br" in on
    assert "permitted;DNS:localhost" in on          # cert TLS da propria interface
    assert pki._name_constraints_line({"domain": "x", "name_constraints": False}) == ""


# --------------------------------------------------------------- secrets
def test_read_secret_precedence(tmp_path, monkeypatch):
    # 1) sem nada -> None
    monkeypatch.delenv("MY_SECRET", raising=False)
    monkeypatch.delenv("MY_SECRET_FILE", raising=False)
    assert pki.read_secret("nao_existe_xyz", "MY_SECRET") is None
    # 2) env var
    monkeypatch.setenv("MY_SECRET", "via-env")
    assert pki.read_secret("nao_existe_xyz", "MY_SECRET") == "via-env"
    # 3) *_FILE tem precedencia sobre env
    f = tmp_path / "s.txt"
    f.write_text("via-arquivo\n")
    monkeypatch.setenv("MY_SECRET_FILE", str(f))
    assert pki.read_secret("nao_existe_xyz", "MY_SECRET") == "via-arquivo"


# --------------------------------------------------------------- cripto de chave
def test_key_encrypt_roundtrip():
    pki._FERNET = None                              # forca recarregar/gerar KEK local no CA_BASE de teste
    data = b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    blob = pki.encrypt_bytes(data)
    assert blob != data
    assert pki.decrypt_bytes(blob) == data


def test_load_kek_rejects_invalid(monkeypatch):
    monkeypatch.setenv("CA_KEK", "isto-nao-e-uma-chave-fernet")
    pki._FERNET = None
    with pytest.raises(EngineError):
        pki.load_kek()
    monkeypatch.delenv("CA_KEK", raising=False)
    pki._FERNET = None


def test_load_int_passphrase(monkeypatch):
    # secret/env tem precedencia
    monkeypatch.setenv("CA_INT_PASS", "passphrase-via-env")
    assert pki.load_int_passphrase() == "passphrase-via-env"
    monkeypatch.delenv("CA_INT_PASS", raising=False)
    # fallback local: gera e persiste em /ca/int_pass
    pki.INT_PASS_PATH.unlink(missing_ok=True)
    pw = pki.load_int_passphrase()
    assert pw and pki.INT_PASS_PATH.exists()
    assert pki.load_int_passphrase() == pw          # estavel (le o arquivo)


def test_ca_lock_serializes():
    from ca_engine import BashEngine
    eng = BashEngine()
    with eng._ca_lock():
        with pytest.raises(EngineError) as ei:      # segundo acesso concorrente -> 503
            with eng._ca_lock(timeout=0):
                pass
        assert ei.value.status == 503
    # apos liberar, adquire normalmente
    with eng._ca_lock(timeout=1):
        pass


def test_p12pass_store_load():
    from ca_engine import BashEngine
    (pki.INT / "newcerts").mkdir(parents=True, exist_ok=True)
    pki._FERNET = None
    eng = BashEngine()
    eng._store_p12pass("2000", "senha-escolhida-na-emissao")
    blob = (pki.INT / "newcerts" / "2000.p12pass.enc")
    assert blob.exists()
    assert b"senha-escolhida" not in blob.read_bytes()        # guardada cifrada
    assert eng._load_p12pass("2000") == "senha-escolhida-na-emissao"
    assert eng._load_p12pass("9999") is None                  # inexistente
    eng._store_p12pass("2001", "")                            # vazio nao guarda
    assert eng._load_p12pass("2001") is None
