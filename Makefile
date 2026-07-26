# certward - atalhos de operacao (Docker)
# Uso:  make <alvo>   (ex: make up, make issue NAME=... , make backup BACKUP_PASS=... )

COMPOSE := docker compose -f docker/docker-compose.yml
EXEC    := $(COMPOSE) exec -T webui
VOLUME  := docker_ca-data
IMAGE   := certward:latest

.DEFAULT_GOAL := help
.PHONY: help up down clean rebuild logs ps issue revoke crl ls expiring shell backup restore reset-admin

help: ## Lista os alvos
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

up: ## Sobe a stack (build + start)
	@[ -f docker/.env ] || cp docker/.env.example docker/.env
	$(COMPOSE) up -d --build

down: ## Para a stack (mantem o volume/estado)
	$(COMPOSE) down

clean: ## Para a stack e APAGA o volume (perde a CA!)
	$(COMPOSE) down -v

rebuild: ## Reconstroi as imagens do zero
	$(COMPOSE) build --no-cache

logs: ## Segue os logs de todos os servicos
	$(COMPOSE) logs -f

ps: ## Status dos servicos
	$(COMPOSE) ps

# A inicializacao/config e feita pelo ASSISTENTE na interface web (primeiro login).

issue: ## Emite cert. Ex: make issue NAME=app1.capsule.lab.br PROFILE=server SANS="DNS:app1.capsule.lab.br,IP:10.0.0.10" P12=senha
	@test -n "$(NAME)" || { echo "Informe NAME=<hostname>"; exit 1; }
	$(EXEC) bash -lc 'P12_PASS="$(P12)" /opt/ca-app/new_cert.sh "$(NAME)" "$(or $(PROFILE),server)" "$(SANS)"'

revoke: ## Revoga cert por serial. Ex: make revoke SERIAL=1001 REASON=keyCompromise
	@test -n "$(SERIAL)" || { echo "Informe SERIAL=<serial hex>"; exit 1; }
	$(EXEC) bash -lc '/opt/ca-app/revoke-cert.sh /ca/intermediate/newcerts/$(SERIAL).pem "$(or $(REASON),superseded)"'

crl: ## Regenera e publica a CRL da intermediaria
	$(EXEC) bash -lc '/opt/ca-app/gen-crl.sh'

ls: ## Lista os certificados do index.txt
	$(EXEC) bash -lc 'column -t -s"$$(printf "\t")" /ca/intermediate/index.txt 2>/dev/null || cat /ca/intermediate/index.txt'

expiring: ## Certs que expiram em breve. Ex: make expiring DAYS=30
	$(EXEC) bash -lc '/opt/ca-app/check-expiring.sh $(or $(DAYS),30)'

shell: ## Abre um shell no container webui
	$(COMPOSE) exec webui bash

backup: ## Backup CIFRADO do volume -> ./ca-backup.tgz.enc  (requer BACKUP_PASS=<senha>)
	@test -n "$(BACKUP_PASS)" || { echo "Informe BACKUP_PASS=<senha forte>"; exit 1; }
	docker run --rm -e BACKUP_PASS='$(BACKUP_PASS)' --entrypoint sh -v $(VOLUME):/ca:ro $(IMAGE) \
	  -c 'tar czf - -C /ca . | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASS' > ca-backup.tgz.enc
	@echo "backup cifrado (AES-256) salvo em ./ca-backup.tgz.enc"

restore: ## Restaura ./ca-backup.tgz.enc para o volume (SOBRESCREVE tudo; requer BACKUP_PASS)
	@test -n "$(BACKUP_PASS)" || { echo "Informe BACKUP_PASS=<senha usada no backup>"; exit 1; }
	@test -f ca-backup.tgz.enc || { echo "ca-backup.tgz.enc nao encontrado no diretorio atual"; exit 1; }
	docker run --rm -e BACKUP_PASS='$(BACKUP_PASS)' --entrypoint sh -v $(VOLUME):/ca -v "$$PWD":/backup $(IMAGE) \
	  -c 'set -e; openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_PASS -in /backup/ca-backup.tgz.enc -out /tmp/r.tgz; tar tzf /tmp/r.tgz >/dev/null; find /ca -mindepth 1 -delete; tar xzf /tmp/r.tgz -C /ca; rm -f /tmp/r.tgz'
	@echo "restaurado. Rode 'make up' se a stack estiver parada."

reset-admin: ## Esquece a senha do admin (volta a usar ADMIN_PASS do docker/.env no proximo login)
	$(EXEC) sh -c 'rm -f /ca/admin.json' && echo "admin.json removido; proximo login usa ADMIN_PASS do docker/.env"
