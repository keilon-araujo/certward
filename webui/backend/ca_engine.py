#!/usr/bin/env python3
# ============================================================================
# ca_engine.py — abstracao do MOTOR de CA.
#
#   CAEngine (interface)  <-  BashEngine (adaptador atual: scripts + openssl)
#
# O control plane (app.py) so fala com a interface. Trocar o motor para
# step-ca no futuro = escrever um StepCaEngine(CAEngine) e plugar em get_engine().
# ============================================================================
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

import pki
from pki import EngineError

OCSP_URL = os.environ.get("OCSP_URL", "http://ocsp:2560")   # responder interno (Docker)
_SERIAL_RE = re.compile(r"ISSUED_SERIAL=([0-9A-Fa-f]+)")


def _shred(p: Path):
    """Sobrescreve e apaga um arquivo de chave em texto claro (best-effort)."""
    try:
        if p.exists():
            with open(p, "r+b") as f:
                n = os.fstat(f.fileno()).st_size
                f.seek(0)
                f.write(secrets.token_bytes(n))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass
    p.unlink(missing_ok=True)


@dataclass
class Download:
    """Descreve um download; a camada web converte em FileResponse/Response."""
    filename: str
    media_type: str = "application/octet-stream"
    path: Path | None = None
    content: bytes | None = None


class CAEngine(ABC):
    @abstractmethod
    def initialize(self, cfg: dict, passphrase: str) -> str: ...
    @abstractmethod
    def status(self) -> dict: ...
    @abstractmethod
    def list_certs(self) -> list: ...
    @abstractmethod
    def cert_detail(self, serial: str) -> dict: ...
    @abstractmethod
    def issue(self, name: str, profile: str, sans: str, p12_password: str) -> str: ...
    @abstractmethod
    def renew(self, serial: str, profile: str, sans: str, p12_password: str,
              revoke_old: bool, reason: str) -> str: ...
    @abstractmethod
    def revoke(self, serial: str, reason: str) -> str: ...
    @abstractmethod
    def regenerate_crl(self) -> str: ...
    @abstractmethod
    def ocsp_status(self, serial: str) -> dict: ...
    @abstractmethod
    def ca_file(self, artifact: str) -> Download: ...
    @abstractmethod
    def download(self, serial: str, kind: str) -> Download: ...


class BashEngine(CAEngine):
    """Motor atual: scripts bash (new_cert.sh, revoke-cert.sh, ...) + openssl CLI."""

    # ------------------------------------------------------------------ util
    def _run(self, script: str, args, extra_env=None, timeout=600) -> str:
        path = pki.SCRIPTS / script
        if not path.exists():
            raise EngineError(500, f"script nao encontrado: {path}")
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        try:
            p = subprocess.run(["bash", str(path), *args], capture_output=True,
                               text=True, env=env, cwd=str(pki.CA_BASE), timeout=timeout)
        except subprocess.TimeoutExpired:
            raise EngineError(504, f"{script} excedeu o tempo limite")
        log = (p.stdout or "") + (p.stderr or "")
        if p.returncode != 0:
            raise EngineError(400, f"{script} falhou (rc={p.returncode}):\n{log}")
        return log

    def _cert_pem(self, serial: str) -> Path:
        if not pki.NAME_RE.match(serial):
            raise EngineError(400, "serial invalido")
        pem = pki.INT / "newcerts" / f"{serial}.pem"
        if not pem.exists():
            raise EngineError(404, "certificado nao encontrado")
        return pem

    def _protect_key(self, serial: str, slug: str):
        """Cifra a chave do assinante em repouso e apaga o texto claro.
        A chave por-serial vira newcerts/<serial>.key.enc; a chave de trabalho
        por-CN (private/<slug>.key) e destruida."""
        if not serial:
            return
        plain = pki.INT / "newcerts" / f"{serial}.key"
        enc = pki.INT / "newcerts" / f"{serial}.key.enc"
        if plain.exists() and not enc.exists():
            enc.write_bytes(pki.encrypt_bytes(plain.read_bytes()))
            os.chmod(enc, 0o400)
            _shred(plain)
        _shred(pki.INT / "private" / f"{slug}.key")

    def _load_key(self, serial: str, slug: str) -> bytes | None:
        """Devolve a chave do assinante em PEM (texto claro), decifrando se preciso.
        Ordem: cifrada por-serial -> texto claro por-serial (legado) -> por-CN (legado)."""
        enc = pki.INT / "newcerts" / f"{serial}.key.enc"
        if enc.exists():
            try:
                return pki.decrypt_bytes(enc.read_bytes())
            except Exception:
                raise EngineError(500, "falha ao decifrar a chave (KEK incorreta?)")
        for legacy in (pki.INT / "newcerts" / f"{serial}.key", pki.INT / "private" / f"{slug}.key"):
            if legacy.exists():
                return legacy.read_bytes()
        return None

    def _store_p12pass(self, serial: str, pw: str):
        """Guarda (cifrada com a KEK) a senha do PKCS#12 escolhida na emissao,
        para o bundle usar a MESMA senha que o usuario definiu/aceitou."""
        if not serial or not pw:
            return
        dst = pki.INT / "newcerts" / f"{serial}.p12pass.enc"
        dst.write_bytes(pki.encrypt_bytes(pw.encode()))
        os.chmod(dst, 0o400)

    def _load_p12pass(self, serial: str) -> str | None:
        src = pki.INT / "newcerts" / f"{serial}.p12pass.enc"
        if src.exists():
            try:
                return pki.decrypt_bytes(src.read_bytes()).decode()
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------ setup
    def initialize(self, cfg: dict, passphrase: str) -> str:
        if pki.ca_present():
            raise EngineError(409, "CA ja inicializada")
        if pki.LOCK_PATH.exists():
            raise EngineError(409, "configuracao ja em andamento")
        if not pki.OPENSSL_TMPL.exists():
            raise EngineError(500, f"template nao encontrado: {pki.OPENSSL_TMPL}")
        pki.CA_BASE.mkdir(parents=True, exist_ok=True)
        pki.LOCK_PATH.write_text("1")
        try:
            pki.CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            pki.write_ca_env(cfg)
            pki.render_openssl_cnf(cfg)
            log = self._run("init-ca.sh", [], extra_env={"CA_ROOT_PASS": passphrase}, timeout=900)
        except BaseException:
            for f in (pki.CONFIG_PATH, pki.ENV_PATH, pki.OPENSSL_CNF):
                f.unlink(missing_ok=True)
            for d in (pki.ROOT, pki.INT, pki.WEB, pki.TLS_DIR):
                shutil.rmtree(d, ignore_errors=True)
            raise
        finally:
            pki.LOCK_PATH.unlink(missing_ok=True)
        return log

    # ------------------------------------------------------------------ leitura
    def status(self) -> dict:
        certs = pki.parse_index() if pki.ca_present() else []
        return {
            "initialized": pki.ca_present(),
            "configured": pki.CONFIG_PATH.exists(),
            "config": pki.load_config(),
            "root": pki.ca_summary(pki.ROOT / "certs" / "ca.crt"),
            "intermediate": pki.ca_summary(pki.INT / "certs" / "intermediate.crt"),
            "ocsp": pki.ca_summary(pki.INT / "certs" / "ocsp.crt"),
            "crl": pki.crl_info(),
            "counts": {
                "total": len(certs),
                "valido": sum(c["status"] == "valido" for c in certs),
                "revogado": sum(c["status"] == "revogado" for c in certs),
                "expirado": sum(c["status"] == "expirado" for c in certs),
                "expirando_30d": sum(
                    c["status"] == "valido" and c["days_left"] is not None and c["days_left"] <= 30
                    for c in certs),
            },
        }

    def list_certs(self) -> list:
        return pki.parse_index()

    def cert_detail(self, serial: str) -> dict:
        pem = self._cert_pem(serial)
        c = pki.load_cert(pem)
        row = next((r for r in pki.parse_index() if r["serial"] == serial), {})
        return {
            **row,
            "subject_full": c.subject.rfc4514_string(),
            "issuer": c.issuer.rfc4514_string(),
            "not_before": c.not_valid_before_utc.isoformat(),
            "not_after": c.not_valid_after_utc.isoformat(),
            "sha256": pki.fingerprint(c),
            "decoded": pki.decode_cert(c),
            "pem": pem.read_text(),
        }

    # ------------------------------------------------------------------ escrita
    def issue(self, name: str, profile: str, sans: str, p12_password: str) -> str:
        # p12_password: senha do PKCS#12 escolhida na emissao (a UI sugere 30
        # chars aleatorios; o usuario pode editar). Guardada cifrada e usada no
        # bundle. Se vazia, o download gera uma aleatoria.
        if not pki.ca_present():
            raise EngineError(409, "CA nao inicializada")
        if not pki.WILDCARD_RE.match(name):
            raise EngineError(400, "nome invalido (use letras, numeros, . _ - ; wildcard: *.dominio)")
        if profile not in pki.PROFILES:
            raise EngineError(400, "perfil invalido")
        log = self._run("new_cert.sh", [name, profile, sans], timeout=300)
        m = _SERIAL_RE.search(log)
        serial = m.group(1) if m else ""
        self._protect_key(serial, pki.fname(name))
        self._store_p12pass(serial, p12_password)
        return log

    def revoke(self, serial: str, reason: str) -> str:
        if reason not in pki.REASONS:
            raise EngineError(400, "motivo invalido")
        pem = self._cert_pem(serial)
        return self._run("revoke-cert.sh", [str(pem), reason], timeout=120)

    def renew(self, serial: str, profile: str, sans: str, p12_password: str,
              revoke_old: bool, reason: str) -> str:
        # Renovacao = REKEY: emite um cert novo (serial e chave novos), boa
        # pratica de PKI. A chave do cert antigo permanece cifrada por-serial,
        # entao o cert antigo ainda pode ser baixado ate expirar/ser revogado.
        certpem = self._cert_pem(serial)
        if profile not in pki.PROFILES:
            raise EngineError(400, "perfil invalido")
        cn = pki.common_name(pki.load_cert(certpem))
        slug = pki.fname(cn)
        if not pki.WILDCARD_RE.match(cn):
            raise EngineError(400, "CN do certificado antigo invalido")
        if revoke_old:
            if reason not in pki.REASONS:
                raise EngineError(400, "motivo invalido")
            self._run("revoke-cert.sh", [str(certpem), reason], timeout=120)
        # limpa os arquivos de trabalho por-CN (o novo cert usa novo serial/chave)
        for p in (pki.INT / "certs" / f"{slug}.crt", pki.INT / "certs" / f"{slug}.chain.crt",
                  pki.INT / "private" / f"{slug}.key", pki.INT / "reqs" / f"{slug}.csr"):
            p.unlink(missing_ok=True)
        log = self._run("new_cert.sh", [cn, profile, sans], timeout=300)
        m = _SERIAL_RE.search(log)
        newserial = m.group(1) if m else ""
        self._protect_key(newserial, slug)
        self._store_p12pass(newserial, p12_password)
        return log

    def regenerate_crl(self) -> str:
        return self._run("gen-crl.sh", [], timeout=120)

    # ------------------------------------------------------------------ OCSP
    def ocsp_status(self, serial: str) -> dict:
        certpem = self._cert_pem(serial)
        issuer = pki.INT / "certs" / "intermediate.crt"
        cachain = pki.INT / "certs" / "ca-chain.crt"
        try:
            p = subprocess.run(
                ["openssl", "ocsp", "-CAfile", str(cachain), "-issuer", str(issuer),
                 "-cert", str(certpem), "-url", OCSP_URL, "-no_nonce"],
                capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            return {"status": "erro", "detail": "timeout ao consultar o OCSP", "url": OCSP_URL}
        out = ((p.stdout or "") + (p.stderr or "")).lower()
        status = "good" if ": good" in out else "revoked" if ": revoked" in out \
            else "unknown" if ": unknown" in out else "erro"
        return {"status": status, "verify_ok": "response verify ok" in out, "url": OCSP_URL}

    # ------------------------------------------------------------------ downloads
    def ca_file(self, artifact: str) -> Download:
        path = pki.CA_FILES.get(artifact)
        if not path or not path.exists():
            raise EngineError(404, "artefato nao encontrado")
        return Download(filename=artifact, path=path)

    def download(self, serial: str, kind: str) -> Download:
        certpem = self._cert_pem(serial)
        cn = pki.common_name(pki.load_cert(certpem))
        slug = pki.fname(cn)
        if not pki.NAME_RE.match(slug):
            raise EngineError(400, "CN do certificado nao mapeavel para arquivo")
        if kind == "bundle":
            return self._bundle(serial, slug, cn)
        if kind == "cert":
            return Download(filename=f"{slug}.crt", path=certpem)
        if kind == "chain":
            data = certpem.read_bytes() + (pki.INT / "certs" / "ca-chain.crt").read_bytes()
            return Download(filename=f"{slug}.chain.crt", content=data)
        if kind == "key":
            keydata = self._load_key(serial, slug)
            if keydata is None:
                raise EngineError(404, "chave nao encontrada para este serial")
            return Download(filename=f"{slug}.key", content=keydata)
        raise EngineError(400, "tipo invalido")

    def _make_p12(self, certpem: Path, keydata: bytes, cachain: Path, cn: str, pw: str) -> bytes:
        """Gera um PKCS#12 escrevendo a chave decifrada num arquivo temporario
        efemero (fora do volume), destruido ao fim."""
        with tempfile.NamedTemporaryFile("wb", suffix=".key", delete=True) as tf:
            tf.write(keydata)
            tf.flush()
            try:
                p = subprocess.run(
                    ["openssl", "pkcs12", "-export", "-inkey", tf.name, "-in", str(certpem),
                     "-certfile", str(cachain), "-name", cn, "-passout", "env:BUNDLE_PW"],
                    capture_output=True, env={**os.environ, "BUNDLE_PW": pw}, timeout=30)
            except subprocess.TimeoutExpired:
                raise EngineError(504, "timeout ao gerar o PKCS#12")
        if p.returncode != 0:
            raise EngineError(500, "falha ao gerar o PKCS#12: " + p.stderr.decode(errors="ignore")[:200])
        return p.stdout

    def _bundle(self, serial: str, slug: str, cn: str) -> Download:
        certpem = self._cert_pem(serial)
        keydata = self._load_key(serial, slug)
        cachain = pki.INT / "certs" / "ca-chain.crt"
        if keydata is None or not cachain.exists():
            raise EngineError(404, "cert/chave nao encontrados para este serial")
        pw = self._load_p12pass(serial) or pki.random_pw(30)   # a senha definida na emissao, se houver
        p12 = self._make_p12(certpem, keydata, cachain, cn, pw)
        dec = pki.decode_cert(pki.load_cert(certpem))
        sans = next((e["value"] for e in dec["extensions"] if e["name"] == "subjectAltName"), [])
        chain_bytes = certpem.read_bytes() + cachain.read_bytes()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{slug}.crt", certpem.read_bytes())
            z.writestr(f"{slug}.key", keydata)
            z.writestr(f"{slug}.chain.crt", chain_bytes)
            z.writestr(f"{slug}.p12", p12)
            z.writestr("PASS.txt", pw + "\n")
            z.writestr("LEIAME.txt", _bundle_readme(slug, cn, dec, sans))
        return Download(filename=f"{slug}.bundle.zip", media_type="application/zip",
                        content=buf.getvalue())


def _bundle_readme(slug: str, cn: str, dec: dict, sans) -> str:
    from datetime import datetime, timezone

    def pair(a):
        return ", ".join(p["attr"] + "=" + p["value"] for p in a)
    lines = [
        f"Pacote do certificado: {cn}",
        f"Gerado em: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "", "ARQUIVOS",
        f"  {slug}.crt         certificado (PEM)",
        f"  {slug}.key         chave privada (PEM, sem senha)",
        f"  {slug}.chain.crt   certificado + intermediaria + raiz (use no F5 BIG-IP)",
        f"  {slug}.p12         PKCS#12 (use no A10 Thunder)",
        "  PASS.txt          senha do arquivo .p12 (definida na emissao; 30 chars aleatorios por padrao)",
        "", "IDENTIDADE",
        f"  Subject : {pair(dec.get('subject', []))}",
        f"  Issuer  : {pair(dec.get('issuer', []))}",
        f"  SANs    : {', '.join(sans) if sans else '-'}",
        f"  Validade: {dec.get('not_before','')[:19]} -> {dec.get('not_after','')[:19]}",
        f"  SHA-256 : {dec.get('fingerprints', {}).get('sha256','')}",
        "", "USO",
        "  F5 BIG-IP : importe o .crt + .key e use o .chain.crt como Certificate Chain.",
        "  A10 Thunder: importe o .p12 usando a senha do PASS.txt.",
        "",
        "ATENCAO: a senha do .p12 esta neste mesmo pacote (PASS.txt). Guarde o zip",
        "com cuidado - quem tiver o pacote tem a chave privada.",
    ]
    return "\n".join(lines) + "\n"


_ENGINE: CAEngine | None = None


def get_engine() -> CAEngine:
    """Retorna o motor ativo (hoje BashEngine; amanha StepCaEngine)."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = BashEngine()
    return _ENGINE
