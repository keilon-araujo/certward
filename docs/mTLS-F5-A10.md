# mTLS no F5 BIG-IP e no A10 Thunder — Capsule Corp CA

O objetivo do mTLS aqui: o balanceador termina o TLS e **exige um certificado de
cliente** emitido pela Capsule Corp CA. Sem cert de cliente válido (e não
revogado), a conexão é recusada.

Peças que a CA entrega:
- `ca-chain.crt` — intermediária + raiz (bundle de confiança).
- `<app>.chain.crt` — cert do servidor + a chain (certificado que o VS apresenta).
- `<app>.p12` — mesmo material em PKCS#12 (import mais fácil no A10).
- `http://ca.capsule.lab.br/ca.crl` e `http://ocsp.capsule.lab.br` — revogação.

Gere um cert de cliente para testar (pela UI, aba **Emitir**, ou via `make`):
```bash
make issue NAME=cliente1.capsule.lab.br PROFILE=client SANS="DNS:cliente1.capsule.lab.br,email:cliente1@capsule.lab.br"
```

---

## F5 BIG-IP (LTM)

### 1. Importar certificados/chaves (System ▸ Certificate Management ▸ Traffic Certificate Management)
- **SSL Certificate**: importe o cert do servidor `app1.capsule.lab.br.crt` e a `app1.capsule.lab.br.key`.
- **Certificate Chain / CA bundle**: importe `ca-chain.crt` como um *Certificate Bundle* (ex.: nome `capsule-ca-bundle`). É o que valida o cert do cliente **e** completa a chain do servidor.

### 2. Client SSL profile (Local Traffic ▸ Profiles ▸ SSL ▸ Client)
- **Certificate / Key**: cert e chave do servidor.
- **Chain**: `capsule-ca-bundle` (ou só a intermediária).
- **Client Certificate**: `require`  ← isto liga o mTLS.
- **Trusted Certificate Authorities**: `capsule-ca-bundle`.
- **Advertised Certificate Authorities**: `capsule-ca-bundle` (o F5 informa ao browser quais CAs aceita).
- **Certificate Chain Traversal Depth**: `2` (leaf → intermediária → raiz).

### 3. Revogação (escolha um)
- **CRL**: baixe/aponte a CRL `http://ca.capsule.lab.br/ca.crl`. O F5 usa CRL via arquivo importado ou CRLDP.
- **OCSP** (recomendado, tempo real): Local Traffic ▸ Profiles ▸ **OCSP Stapling / Auth ▸ OCSP Responder** apontando para `http://ocsp.capsule.lab.br`, e associe um **Auth Profile (SSL OCSP)** ao Virtual Server.

### 4. Passar a identidade do cliente para o backend (iRule)
```tcl
when CLIENTSSL_CLIENTCERT {
    set ccert [SSL::cert 0]
    if { $ccert ne "" } {
        HTTP::header replace X-SSL-Client-CN     [X509::subject $ccert]
        HTTP::header replace X-SSL-Client-Serial [X509::serial_number $ccert]
        HTTP::header replace X-SSL-Client-Verify "SUCCESS"
    }
}
```
Associe o Client SSL profile, o Auth profile (OCSP/CRL) e a iRule ao **Virtual Server**.

---

## A10 Thunder (ACOS / AX)

### 1. Importar material (config ou GUI ▸ ADC ▸ SSL Management)
```
import ssl-cert app1 pfx use-mgmt-port scp://user@host/path/app1.capsule.lab.br.p12  pfx-password <senha>
import ssl-ca-cert capsule-ca use-mgmt-port scp://user@host/path/ca-chain.crt
import ssl-crl capsule-crl use-mgmt-port http://ca.capsule.lab.br/ca.crl
```

### 2. client-ssl template (exige cert do cliente)
```
slb template client-ssl cs-mtls-capsule
  cert app1
  key  app1
  chain-cert capsule-ca
  ca-cert capsule-ca
  auth-username default-subject-cn
  client-certificate Require        ! liga o mTLS
  crl capsule-crl                   ! ou: ocsp-stapling / ocsp
```

### 3. Aplicar no Virtual Port (HTTPS)
```
slb virtual-server vs-app1 10.0.0.10
  port 443 https
    template client-ssl cs-mtls-capsule
    service-group sg-app1-http
```

### 4. Revogação por OCSP (alternativa à CRL)
```
slb template ocsp-authentication oa-capsule
  ocsp-url http://ocsp.capsule.lab.br
! associe ao template client-ssl no lugar do "crl capsule-crl"
```

### 5. Repassar identidade ao backend
Use um **aFleX** (equivalente ao iRule) ou insira headers via `http-template` para
propagar CN/serial do cert de cliente ao servidor de aplicação.

---

## Teste rápido (linha de comando)

```bash
# Deve FUNCIONAR (com cert de cliente):
curl -v https://app1.capsule.lab.br/ \
  --cacert /ca/web/ca-chain.crt \
  --cert  /ca/intermediate/certs/cliente1.capsule.lab.br.crt \
  --key   /ca/intermediate/private/cliente1.capsule.lab.br.key

# Deve FALHAR (sem cert de cliente) -> handshake recusado:
curl -v https://app1.capsule.lab.br/ --cacert /ca/web/ca-chain.crt

# Depois de revogar o cliente1 (pela UI ou 'make revoke SERIAL=<serial> REASON=keyCompromise'),
# o F5/A10 deve recusar mesmo com o cert apresentado.
```
