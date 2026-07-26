# certward - imagem unica (webui / ocsp / crl usam a mesma imagem)
# Codigo em /opt/ca-app | estado da CA no volume montado em /ca
# Roda como usuario NAO-root 'app' (uid 10001) via user-entrypoint.sh.
FROM python:3.12.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl bash gosu \
    && rm -rf /var/lib/apt/lists/*

# usuario nao-root que roda a aplicacao
RUN groupadd -r -g 10001 app && useradd -r -u 10001 -g app -m -d /home/app app

# deps python primeiro (cache de camada)
COPY webui/backend/requirements.txt /opt/ca-app/webui/backend/requirements.txt
RUN pip install --no-cache-dir -r /opt/ca-app/webui/backend/requirements.txt

# codigo da aplicacao (NAO fica no volume /ca, para nao ser escondido por ele).
# Os scripts do motor (scripts/) sao achatados em /opt/ca-app (= SCRIPTS_DIR).
# O openssl.cnf operativo NAO e copiado: e o /ca/openssl.cnf renderizado do template.
COPY scripts/openssl.cnf.tmpl /opt/ca-app/openssl.cnf.tmpl
COPY scripts/*.sh /opt/ca-app/
COPY webui /opt/ca-app/webui
COPY docker/entrypoint-ocsp.sh docker/entrypoint-crl.sh docker/user-entrypoint.sh /opt/ca-app/docker/
RUN chmod +x /opt/ca-app/*.sh /opt/ca-app/docker/*.sh

# CONF aponta para o openssl.cnf RENDERIZADO pelo setup no volume de dados.
# SCRIPTS_DIR (codigo) fica separado de CA_BASE (dados) para o volume nao esconder.
ENV CA_BASE=/ca \
    CONF=/ca/openssl.cnf \
    SCRIPTS_DIR=/opt/ca-app \
    PYTHONUNBUFFERED=1

WORKDIR /opt/ca-app/webui/backend
EXPOSE 8080
# user-entrypoint ajusta o dono de /ca (como root) e dropa para 'app'.
ENTRYPOINT ["/opt/ca-app/docker/user-entrypoint.sh"]
# comando padrao = webui; ocsp/crl sobrescrevem via compose (viram args do entrypoint)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
