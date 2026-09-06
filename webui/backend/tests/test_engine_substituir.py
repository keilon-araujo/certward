"""Renovacao por CSR de um nome que ja tem certificado (achado de 06/09/2026).

O new_cert.sh recusa emitir quando certs/<nome>.crt existe. Com `substituir`,
o motor arquiva os arquivos de trabalho por-CN ANTES de chamar o script e deixa
a serie anterior intacta em newcerts/ — e o que faz a renovacao pela API
funcionar sem revogar nada por baixo dos panos.
"""
import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import ca_engine
import pki

CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n"


def _cert_pem(cn: str, serial: int) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    agora = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(agora).not_valid_after(agora + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def motor(tmp_path, monkeypatch):
    intdir = tmp_path / "intermediate"
    for d in ("certs", "private", "reqs", "newcerts"):
        (intdir / d).mkdir(parents=True)
    monkeypatch.setattr(pki, "INT", intdir)
    monkeypatch.setattr(pki, "ca_present", lambda: True)
    eng = ca_engine.BashEngine()
    chamadas = []

    def _run(script, args, extra_env=None, timeout=600):
        # O que o script veria no disco no momento da chamada.
        chamadas.append((script, list(args),
                         sorted(p.name for p in (intdir / "certs").iterdir())))
        return "==> Assinando\nISSUED_SERIAL=1002\n"

    monkeypatch.setattr(eng, "_run", _run)
    monkeypatch.setattr(eng, "_int_env", lambda: {})
    return eng, intdir, chamadas


def test_substituir_arquiva_o_trabalho_por_nome_antes_de_emitir(motor):
    eng, intdir, chamadas = motor
    (intdir / "certs" / "app.test.lab.crt").write_bytes(_cert_pem("app.test.lab", 0x1001))
    (intdir / "certs" / "app.test.lab.chain.crt").write_text("chain")
    (intdir / "reqs" / "app.test.lab.csr").write_text("csr")
    (intdir / "newcerts" / "1001.pem").write_bytes(_cert_pem("app.test.lab", 0x1001))

    log = eng.issue("app.test.lab", "server", "DNS:app.test.lab", "", "", CSR,
                    substituir=True)

    script, args, no_disco = chamadas[0]
    assert script == "new_cert.sh" and args[0] == "--csr"
    assert "app.test.lab.crt" not in no_disco, "o .crt do nome tinha de sair antes do script"
    assert not (intdir / "reqs" / "app.test.lab.csr").exists()
    # A serie anterior nao e tocada: continua consultavel e baixavel.
    assert (intdir / "newcerts" / "1001.pem").exists()
    assert "serie anterior 1001" in log and "ISSUED_SERIAL=1002" in log


def test_sem_substituir_nao_toca_em_nada(motor):
    eng, intdir, chamadas = motor
    (intdir / "certs" / "app.test.lab.crt").write_bytes(_cert_pem("app.test.lab", 0x1001))
    log = eng.issue("app.test.lab", "server", "DNS:app.test.lab", "", "", CSR)
    _, _, no_disco = chamadas[0]
    assert "app.test.lab.crt" in no_disco   # e o script que recusa, como antes
    assert "Substituindo" not in log


def test_substituir_sem_anterior_e_inofensivo(motor):
    eng, intdir, chamadas = motor
    log = eng.issue("novo.test.lab", "server", "DNS:novo.test.lab", "", "", CSR,
                    substituir=True)
    assert "Substituindo" not in log and "ISSUED_SERIAL=1002" in log
