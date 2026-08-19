"""Tokens de servico da CA (L2 da integracao com plataforma externa).

Uma plataforma que emite certificados automaticamente nao pode autenticar com a
sessao de um administrador: a sessao expira, carrega o poder inteiro da pessoa e
some quando ela sai. O token de servico e identidade propria, com escopo
estreito, validade obrigatoria e revogacao independente.

Formato: `cwt_<kid>_<segredo>`. O `kid` (12 hex) fica em claro e serve de indice
— e como o operador reconhece o token na lista sem que ninguem precise revela-lo.

Verificacao por HMAC-SHA256 com *pepper*, nao bcrypt: o segredo tem 256 bits de
`secrets.token_urlsafe(32)`, entao nao ha entropia baixa a compensar, e a CA
verifica isto a cada emissao. O pepper vive no volume da CA, junto do resto do
estado, com modo 600.

Desenho espelhado de `services/apikeys.py` do CertaSync — mesma ideia, mesmo
vocabulario, para quem opera os dois nao ter de aprender duas coisas.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import pki

PREFIXO = "cwt_"
VALIDADE_PADRAO_DIAS = 365
VALIDADE_MAX_DIAS = 3650

# Escopos por operacao. `certs:issue` NAO implica `certs:revoke`: quem so instala
# nao precisa poder revogar, e revogacao em massa e o estrago mais caro numa CA.
ESCOPOS = ("certs:issue", "certs:read", "certs:revoke")

DESCRICAO = {
    "certs:issue": "Emitir certificado (somente por CSR)",
    "certs:read": "Listar certificados e baixar material publico",
    "certs:revoke": "Revogar certificado",
}

_lock = threading.Lock()


class TokenError(Exception):
    """Token ausente, invalido, expirado ou revogado."""


def _arquivo() -> Path:
    return pki.CA_BASE / "service_tokens.json"


def _pepper_path() -> Path:
    return pki.CA_BASE / ".svc_token_key"


def _pepper() -> bytes:
    env = os.environ.get("CA_SVC_TOKEN_PEPPER", "").strip()
    if env:
        return env.encode()
    caminho = _pepper_path()
    if caminho.exists():
        return caminho.read_text().strip().encode()
    pki.CA_BASE.mkdir(parents=True, exist_ok=True)
    valor = secrets.token_hex(32)
    caminho.write_text(valor)
    try:
        os.chmod(caminho, 0o600)
    except OSError:
        pass
    return valor.encode()


def _digest(segredo: str) -> str:
    return hmac.new(_pepper(), segredo.encode(), hashlib.sha256).hexdigest()


def _carregar() -> dict:
    caminho = _arquivo()
    if not caminho.exists():
        return {}
    try:
        return json.loads(caminho.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _gravar(dados: dict) -> None:
    caminho = _arquivo()
    tmp = caminho.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(caminho)
    try:
        os.chmod(caminho, 0o600)
    except OSError:
        pass


def _agora() -> datetime:
    return datetime.now(timezone.utc)


def _expirado(reg: dict) -> bool:
    exp = reg.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.fromisoformat(exp) <= _agora()
    except Exception:
        return True


def _publico(reg: dict) -> dict:
    """Projecao segura: o segredo e o digest NUNCA saem daqui."""
    return {
        "id": reg.get("id"),
        "name": reg.get("name"),
        "prefix": f"{PREFIXO}{reg.get('id')}",
        "scopes": reg.get("scopes", []),
        "created_at": reg.get("created_at"),
        "created_by": reg.get("created_by"),
        "expires_at": reg.get("expires_at"),
        "last_used_at": reg.get("last_used_at"),
        "active": bool(reg.get("active", True)),
        "expirado": _expirado(reg),
    }


def criar(nome: str, escopos: list, criado_por: str,
          dias: int = VALIDADE_PADRAO_DIAS) -> tuple:
    """Cria um token. Devolve (registro publico, token em claro)."""
    nome = (nome or "").strip()
    if not nome:
        raise ValueError("nome do token e obrigatorio")
    escopos = [e for e in (escopos or []) if e]
    if not escopos:
        raise ValueError("informe ao menos um escopo")
    invalidos = [e for e in escopos if e not in ESCOPOS]
    if invalidos:
        raise ValueError(f"escopo invalido: {', '.join(invalidos)} "
                         f"(use {'/'.join(ESCOPOS)})")
    if not isinstance(dias, int) or not (1 <= dias <= VALIDADE_MAX_DIAS):
        raise ValueError(f"validade deve estar entre 1 e {VALIDADE_MAX_DIAS} dias")

    kid = secrets.token_hex(6)
    segredo = secrets.token_urlsafe(32)
    agora = _agora()
    reg = {
        "id": kid,
        "name": nome,
        "digest": _digest(segredo),
        "scopes": sorted(set(escopos)),
        "created_at": agora.isoformat(),
        "created_by": criado_por or "sistema",
        "expires_at": (agora + timedelta(days=dias)).isoformat(),
        "last_used_at": None,
        "active": True,
    }
    with _lock:
        dados = _carregar()
        if any(r.get("name") == nome for r in dados.values()):
            raise ValueError(f"ja existe token chamado '{nome}'")
        dados[kid] = reg
        _gravar(dados)
    return _publico(reg), f"{PREFIXO}{kid}_{segredo}"


def listar() -> list:
    with _lock:
        dados = _carregar()
    return sorted((_publico(r) for r in dados.values()),
                  key=lambda r: r.get("created_at") or "", reverse=True)


def revogar(kid: str, por: str) -> dict:
    with _lock:
        dados = _carregar()
        if kid not in dados:
            raise KeyError(kid)
        dados[kid]["active"] = False
        dados[kid]["revoked_at"] = _agora().isoformat()
        dados[kid]["revoked_by"] = por or "sistema"
        _gravar(dados)
        return _publico(dados[kid])


def remover(kid: str) -> None:
    with _lock:
        dados = _carregar()
        if kid not in dados:
            raise KeyError(kid)
        del dados[kid]
        _gravar(dados)


def _partes(token: str) -> tuple:
    if not token or not token.startswith(PREFIXO):
        raise TokenError("token de servico invalido")
    resto = token[len(PREFIXO):]
    kid, _, segredo = resto.partition("_")
    if not kid or not segredo:
        raise TokenError("token de servico invalido")
    return kid, segredo


def validar(token: str) -> dict:
    """Valida e devolve o registro publico. Carimba o ultimo uso."""
    kid, segredo = _partes(token)
    with _lock:
        dados = _carregar()
        reg = dados.get(kid)
        # compare_digest mesmo quando o kid nao existe: o tempo de resposta nao
        # deve dizer se o token existe.
        esperado = reg.get("digest", "") if reg else ""
        confere = hmac.compare_digest(esperado or "x" * 64, _digest(segredo))
        if not reg or not confere:
            raise TokenError("token de servico invalido")
        if not reg.get("active", True):
            raise TokenError("token de servico revogado")
        if _expirado(reg):
            raise TokenError("token de servico expirado")
        reg["last_used_at"] = _agora().isoformat()
        _gravar(dados)
        return _publico(reg)
