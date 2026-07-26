"""Fixtures dos testes do control plane. Usa um motor FAKE (não toca em openssl)."""
import os
import sys
import tempfile

# CA_BASE temporario e credencial conhecida ANTES de importar o app/pki.
_TMP = tempfile.mkdtemp(prefix="catest-")
os.environ.setdefault("CA_BASE", _TMP)
os.environ.setdefault("SCRIPTS_DIR", _TMP)
os.environ.setdefault("ADMIN_USER", "admin")
os.environ.setdefault("ADMIN_PASS", "senha-de-teste-1")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest                       # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app as app_module            # noqa: E402
from ca_engine import CAEngine, Download  # noqa: E402
from pki import EngineError          # noqa: E402


class FakeEngine(CAEngine):
    """Implementa a interface do motor com respostas canned e registro de chamadas."""
    def __init__(self):
        self.calls = []

    def initialize(self, cfg, passphrase):
        self.calls.append(("initialize", cfg["domain"], passphrase))
        return "[init] ok"

    def status(self):
        return {"initialized": True, "configured": True,
                "config": {"org": "Test Org", "domain": "test.lab"},
                "root": None, "intermediate": None, "ocsp": None, "crl": None,
                "counts": {"total": 1, "valido": 1, "revogado": 0, "expirado": 0, "expirando_30d": 0}}

    def list_certs(self):
        return [{"serial": "1000", "cn": "a.test.lab", "status": "valido", "profile": "server",
                 "days_left": 100, "not_after": None, "sans": [], "subject": "CN=a",
                 "revoked_at": None, "revoke_reason": None}]

    def cert_detail(self, serial):
        if serial != "1000":
            raise EngineError(404, "certificado nao encontrado")
        return {"serial": "1000", "cn": "a.test.lab", "decoded": {"version": "v3"}, "pem": "PEM"}

    def issue(self, name, profile, sans, p12_password, key_type="ecdsa-p256"):
        self.calls.append(("issue", name, profile, key_type))
        return "[issue] ok"

    def renew(self, serial, profile, sans, p12_password, revoke_old, reason, key_type="ecdsa-p256"):
        self.calls.append(("renew", serial, revoke_old, key_type))
        return "[renew] ok"

    def revoke(self, serial, reason):
        self.calls.append(("revoke", serial, reason))
        return "[revoke] ok"

    def regenerate_crl(self):
        self.calls.append(("crl",))
        return "[crl] ok"

    def ocsp_status(self, serial):
        return {"status": "good", "verify_ok": True, "url": "http://ocsp"}

    def ca_file(self, artifact):
        if artifact != "ca.crt":
            raise EngineError(404, "artefato nao encontrado")
        return Download(filename="ca.crt", content=b"CACERT")

    def download(self, serial, kind):
        if kind not in ("cert", "chain", "key", "bundle"):
            raise EngineError(400, "tipo invalido")
        return Download(filename=f"a.{kind}", content=b"DATA")


@pytest.fixture
def fake_engine():
    return FakeEngine()


@pytest.fixture
def client(fake_engine):
    """Client com a dependencia de auth sobrescrita (sem precisar logar)."""
    prev = app_module.engine
    app_module.engine = fake_engine
    app_module.app.dependency_overrides[app_module.auth] = lambda: "tester"
    app_module.LOGIN_FAILS.clear()
    c = TestClient(app_module.app, base_url="https://testserver")
    c.fake = fake_engine
    yield c
    app_module.app.dependency_overrides.clear()
    app_module.engine = prev


@pytest.fixture
def raw_client(fake_engine):
    """Client SEM override de auth — para testar login/sessao de verdade.
    Isola cada teste: admin.json e session.secret sao recriados do zero."""
    import pki as _pki
    prev = app_module.engine
    app_module.engine = fake_engine
    app_module.LOGIN_FAILS.clear()
    _pki.ADMIN_STORE.unlink(missing_ok=True)             # admin bootstrapa do env (pv=0)
    app_module.SESSION_SECRET_PATH.unlink(missing_ok=True)
    c = TestClient(app_module.app, base_url="https://testserver")
    yield c
    app_module.engine = prev
