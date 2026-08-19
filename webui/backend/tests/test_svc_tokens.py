"""Tokens de servico da CA (L2)."""
import pytest

import svc_tokens as st


@pytest.fixture(autouse=True)
def cofre(tmp_path, monkeypatch):
    import pki
    monkeypatch.setattr(pki, "CA_BASE", tmp_path)
    monkeypatch.delenv("CA_SVC_TOKEN_PEPPER", raising=False)


def test_segredo_aparece_uma_vez_e_nunca_mais():
    reg, token = st.criar("esteira", ["certs:issue"], "admin")
    assert token.startswith("cwt_") and len(token) > 40
    assert "digest" not in reg and "token" not in reg
    listado = st.listar()[0]
    assert token not in str(listado)
    assert listado["prefix"] == f"cwt_{reg['id']}"


def test_valida_e_carimba_ultimo_uso():
    _, token = st.criar("esteira", ["certs:issue", "certs:read"], "admin")
    reg = st.validar(token)
    assert reg["scopes"] == ["certs:issue", "certs:read"]
    assert reg["last_used_at"]


def test_token_adulterado_nao_passa():
    _, token = st.criar("esteira", ["certs:issue"], "admin")
    for ruim in (token[:-4] + "aaaa", "cwt_naoexiste_" + "x" * 40, "qualquer-coisa"):
        with pytest.raises(st.TokenError):
            st.validar(ruim)


def test_pepper_diferente_invalida_tudo(monkeypatch):
    """Levar o service_tokens.json embora nao basta."""
    _, token = st.criar("esteira", ["certs:issue"], "admin")
    monkeypatch.setenv("CA_SVC_TOKEN_PEPPER", "outro-segredo")
    with pytest.raises(st.TokenError):
        st.validar(token)


def test_revogado_e_expirado_nao_passam():
    reg, token = st.criar("esteira", ["certs:issue"], "admin")
    st.revogar(reg["id"], "admin")
    with pytest.raises(st.TokenError, match="revogado"):
        st.validar(token)

    from datetime import datetime, timedelta, timezone
    reg2, token2 = st.criar("velha", ["certs:issue"], "admin", dias=1)
    dados = st._carregar()
    dados[reg2["id"]]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    st._gravar(dados)
    with pytest.raises(st.TokenError, match="expirado"):
        st.validar(token2)


def test_validade_obrigatoria_e_escopo_valido():
    """Token eterno e achado de auditoria; escopo inventado e erro de digitacao."""
    reg, _ = st.criar("padrao", ["certs:issue"], "admin")
    assert reg["expires_at"]
    for dias in (0, -1, st.VALIDADE_MAX_DIAS + 1):
        with pytest.raises(ValueError):
            st.criar(f"x{dias}", ["certs:issue"], "admin", dias=dias)
    with pytest.raises(ValueError, match="escopo invalido"):
        st.criar("y", ["certs:tudo"], "admin")
    with pytest.raises(ValueError):
        st.criar("z", [], "admin")


def test_emitir_nao_implica_revogar():
    """Revogacao em massa e o estrago mais caro numa CA."""
    assert "certs:revoke" in st.ESCOPOS
    _, token = st.criar("so-emite", ["certs:issue"], "admin")
    assert "certs:revoke" not in st.validar(token)["scopes"]
