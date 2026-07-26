#!/usr/bin/env python3
# ============================================================================
# pki.py — biblioteca PURA de PKI: caminhos, parsing do estado da CA e
# decodificacao de certificados (via 'cryptography'). SEM FastAPI, SEM HTTP.
#
# Erros de dominio sobem como EngineError(status, detail); a camada web mapeia
# para HTTP. Isso desacopla o control plane do motor de CA.
# ============================================================================
import json
import os
import re
import secrets
import shlex
import string
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from cryptography.x509.oid import ExtensionOID, NameOID

# --------------------------------------------------------------------------- caminhos
CA_BASE = Path(os.environ.get("CA_BASE", "/ca"))
ROOT = CA_BASE / "root"
INT = CA_BASE / "intermediate"
WEB = CA_BASE / "web"
TLS_DIR = CA_BASE / "tls"
# No Docker o codigo mora fora do volume de dados: SCRIPTS -> /opt/ca-app, CA_BASE -> /ca.
SCRIPTS = Path(os.environ.get("SCRIPTS_DIR", str(CA_BASE)))
CONFIG_PATH = CA_BASE / "config.json"
ENV_PATH = CA_BASE / "ca.env"
LOCK_PATH = CA_BASE / ".setup.lock"
OPENSSL_TMPL = SCRIPTS / "openssl.cnf.tmpl"
OPENSSL_CNF = CA_BASE / "openssl.cnf"
AUDIT_LOG = CA_BASE / "audit.log"
ADMIN_STORE = CA_BASE / "admin.json"
KEK_PATH = CA_BASE / "kek"                    # KEK local (fallback); use Docker secret p/ producao
SECRETS_DIR = Path("/run/secrets")            # onde o Docker monta secrets

CA_FILES = {
    "ca.crt": ROOT / "certs" / "ca.crt",
    "intermediate.crt": INT / "certs" / "intermediate.crt",
    "ca-chain.crt": INT / "certs" / "ca-chain.crt",
    "ca.crl": INT / "crl" / "intermediate.crl",
    "root.crl": ROOT / "crl" / "root.crl",
}

# --------------------------------------------------------------------------- validacao
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
WILDCARD_RE = re.compile(r"^(\*\.)?[A-Za-z0-9._-]{1,120}$")   # hostname ou wildcard *.dominio
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-*[a-z0-9])*\.)+[a-z]{2,}$")
PROFILES = {"server", "client", "dual"}
REASONS = {
    "unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
    "superseded", "cessationOfOperation", "certificateHold",
}
DIGESTS = {"sha256", "sha384", "sha512"}
KEY_SIZES = {2048, 3072, 4096}


class EngineError(Exception):
    """Erro de dominio com codigo HTTP sugerido; a API mapeia para HTTPException."""
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --------------------------------------------------------------------------- util
def fname(cn: str) -> str:
    """Nome de arquivo seguro a partir do CN (o '*' do wildcard vira 'wildcard')."""
    return cn.replace("*", "wildcard")


def random_pw(n: int = 30) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+.?"
    return "".join(secrets.choice(alphabet) for _ in range(n))


# --------------------------------------------------------------------------- secrets / cripto
def read_secret(name: str, env_var: str) -> str | None:
    """Resolve um segredo por precedencia, do mais seguro ao mais simples:
       1) arquivo apontado por <ENV_VAR>_FILE
       2) Docker secret em /run/secrets/<name>
       3) variavel de ambiente <ENV_VAR>
    Devolve None se nada estiver definido."""
    fp = os.environ.get(env_var + "_FILE")
    if fp and Path(fp).exists():
        return Path(fp).read_text().strip()
    sp = SECRETS_DIR / name
    if sp.exists():
        return sp.read_text().strip()
    return os.environ.get(env_var)


_FERNET: Fernet | None = None


def load_kek() -> bytes:
    """KEK (Fernet) para cifrar chaves de assinante em repouso.
    Fonte: Docker secret 'ca_kek' / env CA_KEK; senao gera uma local em /ca/kek.
    A KEK local protege BACKUPS cifrados, mas NAO um vazamento do volume — para
    isso, forneca a KEK via Docker secret (fora do volume)."""
    val = read_secret("ca_kek", "CA_KEK")
    if val:
        try:
            Fernet(val.encode())        # valida formato
        except Exception:
            raise EngineError(500, "CA_KEK invalida (esperado chave Fernet base64 urlsafe de 32 bytes)")
        return val.encode()
    if KEK_PATH.exists():
        return KEK_PATH.read_bytes().strip()
    CA_BASE.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    KEK_PATH.write_bytes(key)
    try:
        os.chmod(KEK_PATH, 0o600)
    except OSError:
        pass
    print("[pki] CA_KEK nao configurada: KEK local gerada em /ca/kek. "
          "Para proteger contra vazamento do volume, use um Docker secret 'ca_kek'.")
    return key


def _fernet() -> Fernet:
    global _FERNET
    if _FERNET is None:
        _FERNET = Fernet(load_kek())
    return _FERNET


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(blob: bytes) -> bytes:
    return _fernet().decrypt(blob)


# --------------------------------------------------------------------------- cert helpers
def load_cert(path: Path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def common_name(cert) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return ""


def san_list(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return [_gn(g) for g in ext.value]


def profile_of(cert) -> str:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        oids = {o.dotted_string for o in eku}
    except x509.ExtensionNotFound:
        return "?"
    server = "1.3.6.1.5.5.7.3.1" in oids
    client = "1.3.6.1.5.5.7.3.2" in oids
    ocsp = "1.3.6.1.5.5.7.3.9" in oids
    if ocsp:
        return "ocsp"
    if server and client:
        return "dual"
    if server:
        return "server"
    if client:
        return "client"
    return "?"


def fingerprint(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def _oidn(oid) -> str:
    n = getattr(oid, "_name", None)
    return oid.dotted_string if (not n or n == "Unknown OID") else n


_GN_LABELS = {
    "DNSName": "DNS", "IPAddress": "IP", "UniformResourceIdentifier": "URI",
    "RFC822Name": "email", "DirectoryName": "dirName", "RegisteredID": "RID",
    "OtherName": "otherName",
}


def _gn(g) -> str:
    label = _GN_LABELS.get(type(g).__name__, type(g).__name__.replace("Name", ""))
    try:
        return f"{label}:{g.value}"
    except Exception:
        return label


def _name_pairs(name):
    pairs = []
    for a in name:
        try:
            key = a.rfc4514_attribute_name
        except Exception:
            key = _oidn(a.oid)
        val = a.value if isinstance(a.value, str) else str(a.value)
        pairs.append({"attr": key, "value": val})
    return pairs


def _pubkey_info(cert):
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return {"type": "RSA", "size": pk.key_size, "exponent": pk.public_numbers().e}
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return {"type": "EC", "curve": pk.curve.name, "size": pk.key_size}
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519"}
    if isinstance(pk, ed448.Ed448PublicKey):
        return {"type": "Ed448"}
    if isinstance(pk, dsa.DSAPublicKey):
        return {"type": "DSA", "size": pk.key_size}
    return {"type": pk.__class__.__name__}


def _decode_extensions(cert):
    out = []
    for ext in cert.extensions:
        v = ext.value
        item = {"name": _oidn(ext.oid), "critical": ext.critical, "value": None}
        try:
            if isinstance(v, x509.BasicConstraints):
                item["value"] = {"ca": v.ca, "path_length": v.path_length}
            elif isinstance(v, x509.KeyUsage):
                usages = [a for a in (
                    "digital_signature", "content_commitment", "key_encipherment",
                    "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
                ) if getattr(v, a)]
                if v.key_agreement:
                    for a in ("encipher_only", "decipher_only"):
                        try:
                            if getattr(v, a):
                                usages.append(a)
                        except ValueError:
                            pass
                item["value"] = usages
            elif isinstance(v, x509.ExtendedKeyUsage):
                item["value"] = [_oidn(o) for o in v]
            elif isinstance(v, x509.SubjectAlternativeName):
                item["value"] = [_gn(g) for g in v]
            elif isinstance(v, x509.SubjectKeyIdentifier):
                item["value"] = v.digest.hex(":").upper()
            elif isinstance(v, x509.AuthorityKeyIdentifier):
                item["value"] = v.key_identifier.hex(":").upper() if v.key_identifier else None
            elif isinstance(v, x509.AuthorityInformationAccess):
                item["value"] = [
                    {"method": _oidn(d.access_method), "location": _gn(d.access_location)} for d in v
                ]
            elif isinstance(v, x509.CRLDistributionPoints):
                uris = []
                for dp in v:
                    for g in (dp.full_name or []):
                        uris.append(_gn(g))
                item["value"] = uris
            else:
                item["value"] = str(v)
        except Exception as e:
            item["value"] = f"(erro ao decodificar: {e})"
        out.append(item)
    return out


def decode_cert(cert):
    now = datetime.now(timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "version": cert.version.name,
        "serial_hex": format(cert.serial_number, "X"),
        "serial_int": str(cert.serial_number),
        "signature_algorithm": _oidn(cert.signature_algorithm_oid),
        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "public_key": _pubkey_info(cert),
        "subject": _name_pairs(cert.subject),
        "issuer": _name_pairs(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_total": (na - nb).days,
        "days_left": (na - now).days,
        "expired": na < now,
        "fingerprints": {
            "sha1": cert.fingerprint(hashes.SHA1()).hex(":").upper(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        },
        "extensions": _decode_extensions(cert),
    }


def decode_pem(pem: str) -> dict:
    try:
        c = x509.load_pem_x509_certificate(pem.strip().encode())
    except Exception as e:
        raise EngineError(400, f"PEM invalido: {e}")
    return decode_cert(c)


# --------------------------------------------------------------------------- estado da CA
def _parse_asn1_time(s: str):
    return datetime.strptime(s, "%y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)


def parse_index():
    """Le intermediate/index.txt e enriquece com dados do cert em newcerts/."""
    idx = INT / "index.txt"
    if not idx.exists():
        return []
    now = datetime.now(timezone.utc)
    rows = []
    for line in idx.read_text().splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        if len(f) < 6:
            continue
        st, exp, rev, serial, _fn, subject = f[0], f[1], f[2], f[3], f[4], f[5]
        entry = {
            "serial": serial,
            "status": {"V": "valido", "R": "revogado", "E": "expirado"}.get(st, st),
            "subject": subject,
            "not_after": _parse_asn1_time(exp).isoformat() if exp else None,
            "revoked_at": None, "revoke_reason": None,
            "cn": subject.split("CN=")[-1].split("/")[0] if "CN=" in subject else "",
            "profile": "?", "sans": [], "days_left": None,
        }
        if st == "R" and rev:
            parts = rev.split(",")
            entry["revoked_at"] = _parse_asn1_time(parts[0]).isoformat()
            if len(parts) > 1:
                entry["revoke_reason"] = parts[1]
        if entry["not_after"]:
            entry["days_left"] = (_parse_asn1_time(exp) - now).days
        pem = INT / "newcerts" / f"{serial}.pem"
        if pem.exists():
            try:
                c = load_cert(pem)
                entry["cn"] = common_name(c) or entry["cn"]
                entry["profile"] = profile_of(c)
                entry["sans"] = san_list(c)
            except Exception:
                pass
        rows.append(entry)
    rows.sort(key=lambda r: r["serial"], reverse=True)
    return rows


def ca_present() -> bool:
    return (ROOT / "certs" / "ca.crt").exists() and (INT / "certs" / "intermediate.crt").exists()


def ca_summary(path: Path):
    if not path.exists():
        return None
    c = load_cert(path)
    return {
        "subject": c.subject.rfc4514_string(),
        "not_before": c.not_valid_before_utc.isoformat(),
        "not_after": c.not_valid_after_utc.isoformat(),
        "serial": format(c.serial_number, "X"),
        "sha256": fingerprint(c),
    }


def crl_info():
    crl_path = INT / "crl" / "intermediate.crl"
    if not crl_path.exists():
        return None
    crl = x509.load_pem_x509_crl(crl_path.read_bytes())
    return {
        "last_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
        "revoked_count": len(crl),
    }


# --------------------------------------------------------------------------- config (wizard)
def load_config():
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            return None
    return None


def _host(value, prefix, domain):
    v = (value or "").strip().lower() or f"{prefix}.{domain}"
    if not DOMAIN_RE.match(v):
        raise EngineError(400, f"host invalido: {v}")
    return v


def _posint(value, default, name, hi=20000):
    try:
        n = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        raise EngineError(400, f"{name} invalido")
    if n <= 0 or n > hi:
        raise EngineError(400, f"{name} fora do intervalo (1..{hi})")
    return n


def resolve_config(b) -> dict:
    """Valida a entrada do wizard e devolve o config resolvido (com defaults)."""
    domain = (b.domain or "").strip().lower()
    if not DOMAIN_RE.match(domain):
        raise EngineError(400, "dominio invalido (ex: capsule.lab.br)")
    org = (b.org or "").strip()
    if not org:
        raise EngineError(400, "organizacao (O) obrigatoria")
    country = (b.country or "BR").strip().upper()
    if len(country) != 2 or not country.isalpha():
        raise EngineError(400, "pais (C) deve ter 2 letras (ex: BR)")
    if not b.passphrase or len(b.passphrase) < 8:
        raise EngineError(400, "a passphrase da raiz precisa de ao menos 8 caracteres")
    if b.digest not in DIGESTS:
        raise EngineError(400, f"digest invalido (use {', '.join(sorted(DIGESTS))})")
    if b.key_size not in KEY_SIZES or b.leaf_key_size not in KEY_SIZES:
        raise EngineError(400, f"tamanho de chave invalido (use {sorted(KEY_SIZES)})")
    return {
        "domain": domain, "org": org,
        "ou": (b.ou or f"{org} CA").strip(),
        "country": country, "state": (b.state or "").strip(), "locality": (b.locality or "").strip(),
        "root_cn": (b.root_cn or f"{org} Root CA").strip(),
        "intermediate_cn": (b.intermediate_cn or f"{org} Intermediate CA").strip(),
        "ca_host": _host(b.ca_host, "ca", domain),
        "ocsp_host": _host(b.ocsp_host, "ocsp", domain),
        "admin_host": _host(b.admin_host, "admin", domain),
        "key_size": b.key_size, "leaf_key_size": b.leaf_key_size,
        "root_days": _posint(b.root_days, 3650, "root_days"),
        "intermediate_days": _posint(b.intermediate_days, 1825, "intermediate_days"),
        "leaf_days": _posint(b.leaf_days, 375, "leaf_days"),
        "crl_days": _posint(b.crl_days, 30, "crl_days"),
        "crl_days_root": _posint(b.crl_days_root, 180, "crl_days_root"),
        "digest": b.digest,
        "name_constraints": bool(getattr(b, "name_constraints", True)),
    }


def _name_constraints_line(cfg) -> str:
    """Linha nameConstraints da intermediaria: limita a CA (criptograficamente)
    a emitir apenas dentro do dominio interno. 'localhost' entra para o cert TLS
    da propria interface admin. IPs ficam sem restricao (SANs de IP continuam
    validos, pois so restringimos DNS)."""
    if not cfg.get("name_constraints", True):
        return ""
    dom = cfg["domain"]
    return f"nameConstraints        = critical, permitted;DNS:{dom}, permitted;DNS:localhost"


def render_openssl_cnf(cfg):
    tmpl = OPENSSL_TMPL.read_text()
    repl = {
        "COUNTRY": cfg["country"], "STATE": cfg["state"], "LOCALITY": cfg["locality"],
        "ORG": cfg["org"], "OU": cfg["ou"], "ROOT_CN": cfg["root_cn"],
        "CA_HOST": cfg["ca_host"], "OCSP_HOST": cfg["ocsp_host"],
        "KEY_SIZE": str(cfg["key_size"]), "DIGEST": cfg["digest"],
        "ROOT_DAYS": str(cfg["root_days"]), "LEAF_DAYS": str(cfg["leaf_days"]),
        "CRL_DAYS": str(cfg["crl_days"]), "CRL_DAYS_ROOT": str(cfg["crl_days_root"]),
        "NAME_CONSTRAINTS_LINE": _name_constraints_line(cfg),
    }
    for k, v in repl.items():
        tmpl = tmpl.replace("{{" + k + "}}", v)
    OPENSSL_CNF.write_text(tmpl)


def write_ca_env(cfg):
    env = {
        "CA_DOMAIN": cfg["domain"], "CA_ORG": cfg["org"], "CA_OU": cfg["ou"],
        "CA_COUNTRY": cfg["country"], "CA_STATE": cfg["state"], "CA_LOCALITY": cfg["locality"],
        "CA_ROOT_CN": cfg["root_cn"], "CA_INT_CN": cfg["intermediate_cn"],
        "CA_OCSP_CN": cfg["ocsp_host"],
        "CA_HOST_CA": cfg["ca_host"], "CA_HOST_OCSP": cfg["ocsp_host"], "CA_HOST_ADMIN": cfg["admin_host"],
        "CA_KEY_SIZE": str(cfg["key_size"]), "CA_LEAF_KEY_SIZE": str(cfg["leaf_key_size"]),
        "CA_ROOT_DAYS": str(cfg["root_days"]), "CA_INT_DAYS": str(cfg["intermediate_days"]),
        "CA_LEAF_DAYS": str(cfg["leaf_days"]), "CA_DIGEST": cfg["digest"],
    }
    body = "# gerado pelo setup a partir de config.json — nao editar a mao\n"
    body += "".join(f"{k}={shlex.quote(str(v))}\n" for k, v in env.items())
    ENV_PATH.write_text(body)
