"""Testes do control plane (FastAPI) com o motor FAKE."""


# ---- endpoints de negocio (auth sobrescrita) ------------------------------
def test_health_no_auth(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    assert r.json()["initialized"] is True


def test_list_certs(client):
    r = client.get("/api/certs")
    assert r.status_code == 200
    assert r.json()[0]["serial"] == "1000"


def test_cert_detail_ok_and_404(client):
    assert client.get("/api/certs/1000").json()["decoded"]["version"] == "v3"
    r = client.get("/api/certs/9999")            # EngineError(404) -> HTTP 404
    assert r.status_code == 404
    assert "detail" in r.json()


def test_issue_calls_engine_and_audits(client):
    r = client.post("/api/certs", json={"name": "x.test.lab", "profile": "server", "sans": ""})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert ("issue", "x.test.lab", "server", "ecdsa-p256") in client.fake.calls   # default ECDSA


def test_issue_key_type_passthrough(client):
    r = client.post("/api/certs", json={"name": "r.test.lab", "profile": "server", "key_type": "rsa-4096"})
    assert r.status_code == 200
    assert ("issue", "r.test.lab", "server", "rsa-4096") in client.fake.calls


def test_revoke_and_renew(client):
    assert client.post("/api/certs/1000/revoke", json={"reason": "superseded"}).status_code == 200
    assert ("revoke", "1000", "superseded") in client.fake.calls
    assert client.post("/api/certs/1000/renew", json={"profile": "server", "revoke_old": False}).status_code == 200
    assert ("renew", "1000", False, "ecdsa-p256") in client.fake.calls


def test_ocsp(client):
    assert client.get("/api/certs/1000/ocsp").json()["status"] == "good"


def test_crl_regenerate(client):
    assert client.post("/api/crl/regenerate").status_code == 200
    assert ("crl",) in client.fake.calls


def test_downloads(client):
    assert client.get("/api/download/ca/ca.crt").status_code == 200
    assert client.get("/api/download/ca/inexistente").status_code == 404   # EngineError(404)
    assert client.get("/api/certs/1000/download/bundle").status_code == 200
    assert client.get("/api/certs/1000/download/xpto").status_code == 400   # EngineError(400)


def test_decode_endpoint(client):
    # PEM invalido -> EngineError(400) mapeado
    assert client.post("/api/decode", json={"pem": "lixo"}).status_code == 400


# ---- fluxo de autenticacao (sem override) ---------------------------------
def test_me_requires_session(raw_client):
    assert raw_client.get("/api/me").status_code == 401


def test_login_bad_then_good(raw_client):
    assert raw_client.post("/api/login", json={"username": "admin", "password": "errada"}).status_code == 401
    r = raw_client.post("/api/login", json={"username": "admin", "password": "senha-de-teste-1"})
    assert r.status_code == 200 and r.json()["user"] == "admin"
    # cookie de sessao persiste no client -> /api/me passa
    assert raw_client.get("/api/me").json()["user"] == "admin"


def test_logout_invalidates(raw_client):
    raw_client.post("/api/login", json={"username": "admin", "password": "senha-de-teste-1"})
    assert raw_client.get("/api/me").status_code == 200
    assert raw_client.post("/api/logout").status_code == 200
    assert raw_client.get("/api/me").status_code == 401


def test_rate_limit(raw_client):
    for _ in range(5):
        raw_client.post("/api/login", json={"username": "admin", "password": "x"})
    # apos FAIL_MAX, bloqueia com 429
    assert raw_client.post("/api/login", json={"username": "admin", "password": "x"}).status_code == 429


def test_change_password_invalidates_old_tokens(raw_client):
    raw_client.post("/api/login", json={"username": "admin", "password": "senha-de-teste-1"})
    assert raw_client.get("/api/me").status_code == 200
    r = raw_client.post("/api/change-password",
                        json={"current": "senha-de-teste-1", "new": "nova-senha-forte-2"})
    assert r.status_code == 200
    # bump de pv invalida o token atual (stateless): 401 sem novo login
    assert raw_client.get("/api/me").status_code == 401
    # senha antiga nao loga mais; a nova sim
    assert raw_client.post("/api/login",
                           json={"username": "admin", "password": "senha-de-teste-1"}).status_code == 401
    assert raw_client.post("/api/login",
                           json={"username": "admin", "password": "nova-senha-forte-2"}).status_code == 200
