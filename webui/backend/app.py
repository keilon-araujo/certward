#!/usr/bin/env python3
# ============================================================================
# app.py — control plane (FastAPI): HTTP, autenticacao por sessao e auditoria.
#
# A logica de CA vive em:
#   pki.py        helpers puros (cripto/parse/config)
#   ca_engine.py  motor (BashEngine hoje; StepCaEngine amanha) via get_engine()
#
# A API so orquestra: valida entrada minima, chama o engine, audita, responde.
# EngineError(status, detail) e mapeado para HTTP pelo exception handler.
#
# Config por ambiente: CA_BASE, SCRIPTS_DIR, ADMIN_USER, ADMIN_PASS, OCSP_URL.
# Rodar:  uvicorn app:app --host 0.0.0.0 --port 8080
# ============================================================================
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import pki
from pki import EngineError
from ca_engine import Download, get_engine

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

ADMIN_USER = pki.read_secret("admin_user", "ADMIN_USER") or "admin"
ADMIN_PASS = pki.read_secret("admin_pass", "ADMIN_PASS")   # Docker secret > *_FILE > env
if not ADMIN_PASS:
    ADMIN_PASS = secrets.token_urlsafe(12)
    print(f"[webui] ADMIN_PASS nao definido. Senha temporaria: {ADMIN_PASS}")

# ---- sessao (token assinado, stateless) / rate-limit ----------------------
COOKIE = "ca_session"
SESSION_TTL = 8 * 3600                      # 8h
SESSION_SECRET_PATH = pki.CA_BASE / "session.secret"   # segredo HMAC persistido no volume
LOGIN_FAILS: dict = {}                     # ip -> {"count":.., "ts":.., "until":..} (best-effort, por processo)
FAIL_MAX = 5
FAIL_LOCK = 300                            # 5 min de bloqueio apos FAIL_MAX

app = FastAPI(title="certward")
engine = get_engine()


@app.exception_handler(EngineError)
async def _engine_error_handler(request: Request, exc: EngineError):
    return JSONResponse(status_code=exc.status, content={"detail": exc.detail})


# ---- autenticacao ---------------------------------------------------------
def _hash_pw(password: str, salt: str | None = None, iterations: int = 200_000):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
    return {"salt": salt, "hash": dk.hex(), "iterations": iterations}


def _verify_pw(password: str, rec: dict) -> bool:
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(rec["salt"]), rec["iterations"])
    return hmac.compare_digest(calc.hex(), rec["hash"])


def ensure_admin() -> dict:
    """Carrega o admin de /ca/admin.json; na 1a vez cria a partir de ADMIN_USER/ADMIN_PASS."""
    if pki.ADMIN_STORE.exists():
        try:
            return json.loads(pki.ADMIN_STORE.read_text())
        except Exception:
            pass
    pki.CA_BASE.mkdir(parents=True, exist_ok=True)
    rec = {"username": ADMIN_USER, "pv": 0, **_hash_pw(ADMIN_PASS)}
    pki.ADMIN_STORE.write_text(json.dumps(rec, indent=2))
    return rec


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else (request.client.host if request.client else "?")


def audit(user: str, action: str, detail: str = ""):
    try:
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "user": user, "action": action, "detail": str(detail)[:800]}
        with open(pki.AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _session_secret() -> bytes:
    """Segredo de assinatura dos tokens, persistido no volume (sobrevive a
    restart e e compartilhado entre workers/replicas, ao contrario de um dict
    em memoria)."""
    if SESSION_SECRET_PATH.exists():
        return SESSION_SECRET_PATH.read_bytes()
    pki.CA_BASE.mkdir(parents=True, exist_ok=True)
    sec = secrets.token_bytes(32)
    SESSION_SECRET_PATH.write_bytes(sec)
    try:
        os.chmod(SESSION_SECRET_PATH, 0o600)
    except OSError:
        pass
    return sec


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _pw_version() -> int:
    try:
        return int(ensure_admin().get("pv", 0))
    except Exception:
        return 0


def _new_session(user: str) -> str:
    """Token stateless: base64(payload).base64(HMAC-SHA256(payload)).
    Sem estado no servidor — a validade e a integridade viajam no proprio token."""
    payload = {"u": user, "exp": int(time.time() + SESSION_TTL), "pv": _pw_version()}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_session_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def auth(request: Request) -> str:
    """Dependencia: exige um token de sessao valido (cookie). Retorna o usuario."""
    tok = request.cookies.get(COOKIE) or ""
    try:
        body, sig = tok.split(".")
        expected = _b64(hmac.new(_session_secret(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(_b64d(body))
        if payload["exp"] < time.time():
            raise ValueError
        if int(payload.get("pv", -1)) != _pw_version():   # troca de senha invalida tokens antigos
            raise ValueError
        return payload["u"]
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "sessao invalida ou expirada")


def _respond(d: Download):
    if d.path is not None:
        return FileResponse(d.path, filename=d.filename, media_type=d.media_type)
    return Response(content=d.content, media_type=d.media_type,
                    headers={"Content-Disposition": f'attachment; filename="{d.filename}"'})


# ---- models ---------------------------------------------------------------
class SetupBody(BaseModel):
    domain: str
    org: str
    ou: str | None = None
    country: str = "BR"
    state: str = ""
    locality: str = ""
    root_cn: str | None = None
    intermediate_cn: str | None = None
    ca_host: str | None = None
    ocsp_host: str | None = None
    admin_host: str | None = None
    key_size: int = 4096
    leaf_key_size: int = 2048
    root_days: int | None = 3650
    intermediate_days: int | None = 1825
    leaf_days: int | None = 375
    crl_days: int | None = 30
    crl_days_root: int | None = 180
    digest: str = "sha256"
    name_constraints: bool = True     # limita a intermediaria ao dominio interno
    passphrase: str = Field(min_length=8)


class IssueBody(BaseModel):
    name: str
    profile: str = "server"
    sans: str = ""
    p12_password: str = ""


class RevokeBody(BaseModel):
    reason: str = "superseded"


class RenewBody(BaseModel):
    profile: str = "server"
    sans: str = ""
    p12_password: str = ""
    revoke_old: bool = True
    reason: str = "superseded"


class DecodeBody(BaseModel):
    pem: str


class LoginBody(BaseModel):
    username: str
    password: str


class PwBody(BaseModel):
    current: str
    new: str = Field(min_length=8)


# ---- rotas: app + auth ----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    if FRONTEND.exists():
        return FRONTEND.read_text()
    return "<h1>Autoridade Certificadora</h1><p>frontend/index.html nao encontrado.</p>"


@app.get("/api/health")
def health():
    return {"status": "ok", "initialized": pki.ca_present()}


@app.get("/api/me")
def me(user: str = Depends(auth)):
    return {"user": user}


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response):
    ip = _client_ip(request)
    now = time.time()
    lf = LOGIN_FAILS.get(ip)
    if lf and lf.get("until", 0) > now:
        raise HTTPException(429, "muitas tentativas; aguarde alguns minutos")
    rec = ensure_admin()
    if not secrets.compare_digest(body.username, rec["username"]) or not _verify_pw(body.password, rec):
        # conta falhas consecutivas dentro da janela FAIL_LOCK; bloqueia apos FAIL_MAX
        n = (lf["count"] + 1) if (lf and now - lf.get("ts", 0) < FAIL_LOCK) else 1
        LOGIN_FAILS[ip] = {"count": n, "ts": now, "until": now + FAIL_LOCK if n >= FAIL_MAX else 0}
        audit(body.username, "login-falha", ip)
        raise HTTPException(401, "usuario ou senha invalidos")
    LOGIN_FAILS.pop(ip, None)
    tok = _new_session(rec["username"])
    response.set_cookie(COOKIE, tok, httponly=True, secure=True, samesite="strict",
                        max_age=SESSION_TTL, path="/")
    audit(rec["username"], "login", ip)
    return {"ok": True, "user": rec["username"]}


@app.post("/api/logout")
def logout(response: Response, user: str = Depends(auth)):
    # token stateless: basta apagar o cookie no cliente
    response.delete_cookie(COOKIE, path="/")
    audit(user, "logout", "")
    return {"ok": True}


@app.post("/api/change-password")
def change_password(body: PwBody, user: str = Depends(auth)):
    rec = ensure_admin()
    if not _verify_pw(body.current, rec):
        raise HTTPException(400, "senha atual incorreta")
    new_pv = int(rec.get("pv", 0)) + 1     # bump de versao invalida todos os tokens antigos
    pki.ADMIN_STORE.write_text(json.dumps(
        {"username": rec["username"], "pv": new_pv, **_hash_pw(body.new)}, indent=2))
    audit(user, "change-password", "")
    return {"ok": True}


@app.get("/api/audit")
def get_audit(user: str = Depends(auth), limit: int = 300):
    if not pki.AUDIT_LOG.exists():
        return []
    lines = pki.AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-limit:]
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except Exception:
            pass
    return out


# ---- rotas: CA (delegam ao engine) ----------------------------------------
@app.get("/api/status")
def status_ep(_: str = Depends(auth)):
    return engine.status()


@app.get("/api/config")
def get_config(_: str = Depends(auth)):
    return {"configured": pki.CONFIG_PATH.exists(), "config": pki.load_config()}


@app.post("/api/setup")
def setup(body: SetupBody, user: str = Depends(auth)):
    cfg = pki.resolve_config(body)
    log = engine.initialize(cfg, body.passphrase)
    audit(user, "setup", cfg["domain"])
    return {"ok": True, "log": log, "config": cfg}


@app.get("/api/certs")
def list_certs(_: str = Depends(auth)):
    return engine.list_certs()


@app.get("/api/certs/{serial}")
def cert_detail(serial: str, _: str = Depends(auth)):
    return engine.cert_detail(serial)


@app.post("/api/decode")
def decode_pem(body: DecodeBody, _: str = Depends(auth)):
    return {"decoded": pki.decode_pem(body.pem)}


@app.post("/api/certs")
def issue(body: IssueBody, user: str = Depends(auth)):
    log = engine.issue(body.name, body.profile, body.sans, body.p12_password)
    audit(user, "emitir", f"{body.name} ({body.profile})")
    return {"ok": True, "log": log}


@app.post("/api/certs/{serial}/revoke")
def revoke(serial: str, body: RevokeBody, user: str = Depends(auth)):
    log = engine.revoke(serial, body.reason)
    audit(user, "revogar", f"serial {serial} ({body.reason})")
    return {"ok": True, "log": log}


@app.post("/api/certs/{serial}/renew")
def renew(serial: str, body: RenewBody, user: str = Depends(auth)):
    log = engine.renew(serial, body.profile, body.sans, body.p12_password, body.revoke_old, body.reason)
    audit(user, "renovar", f"serial {serial} (revogou_antigo={body.revoke_old})")
    return {"ok": True, "log": log}


@app.get("/api/certs/{serial}/ocsp")
def ocsp_check(serial: str, _: str = Depends(auth)):
    return engine.ocsp_status(serial)


@app.post("/api/crl/regenerate")
def regen_crl(user: str = Depends(auth)):
    log = engine.regenerate_crl()
    audit(user, "crl-regenerar", "")
    return {"ok": True, "log": log}


@app.get("/api/download/ca/{artifact}")
def dl_ca(artifact: str, _: str = Depends(auth)):
    return _respond(engine.ca_file(artifact))


@app.get("/api/certs/{serial}/download/{kind}")
def dl_cert(serial: str, kind: str, user: str = Depends(auth)):
    d = engine.download(serial, kind)
    if kind == "bundle":
        audit(user, "bundle-zip", serial)
    return _respond(d)
