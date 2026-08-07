# WebTerm — management commands
COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")
APP := $(shell $(COMPOSE) ps -q app 2>/dev/null)

.PHONY: help setup up down restart logs logs-app token ps dev update backup backup-install test build deploy pull

help: ## Show this list
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Full install (interactive)
	@./setup.sh

up: ## Start (build + start)
	$(COMPOSE) up -d --build

down: ## Stop
	$(COMPOSE) down

restart: ## Restart the gateway
	$(COMPOSE) restart app

logs: ## Live logs (all)
	$(COMPOSE) logs -f

logs-app: ## Live logs, gateway only
	$(COMPOSE) logs -f app

token: ## Show the setup token (if no account yet)
	@# .env first (production install writes it there), then the log marker.
	@# The old version grepped a Romanian log sentence — it broke the moment the
	@# message was reworded, and would break again on translation.
	@# `A || B` where A is a pipeline: the status is the LAST command's, and `cut` always
	@# succeeds — so grep finding nothing still "passed" and BOTH fallbacks were dead code.
	@# On the quick-install path .env holds an empty value, so this printed nothing at all,
	@# with exit 0: the second documented way to recover the token never worked.
	@sed -n 's/^WEBTERM_SETUP_TOKEN=\(..*\)/\1/p' .env 2>/dev/null; \
	 $(COMPOSE) logs app 2>/dev/null | grep -oE 'WEBTERM_SETUP_TOKEN=[A-Za-z0-9_-]+' \
		| tail -1 | cut -d= -f2-

ps: ## Container status
	$(COMPOSE) ps

dev: ## Local dev: backend (uvicorn --reload) + Vite frontend
	PYTHONPATH=gateway .venv/bin/uvicorn app.main:app --reload & cd frontend && npm run dev

update: ## Pull code and rebuild (dev, local build)
	git pull --ff-only && $(COMPOSE) up -d --build

deploy: ## Production deploy from a ghcr image + Traefik/SSL (one command)
	@./deploy.sh

upgrade: ## Production upgrade to the latest version (backup + host files + image + rollback)
	@./upgrade.sh

remove: ## Uninstall WebTerm from this machine (refuses while agents are still enrolled)
	@./remove.sh

pull: ## Pull the latest published image and restart (production)
	$(COMPOSE) -f docker-compose.prod.yml pull && \
	$(COMPOSE) -f docker-compose.prod.yml up -d --remove-orphans

backup: ## Back up data (encrypted, crash-consistent) — wrapper over scripts/backup.sh
	@# The old target tarred the live volume directly: the archive was UNENCRYPTED (it
	@# contains data/secret — the vault key — and the fleet signing key) AND torn (raw
	@# webterm.db + -wal captured at different instants). scripts/backup.sh uses SQLite's
	@# online backup API and refuses to write plaintext unattended. One backup path, not two.
	@WEBTERM_BACKUP_DIR="$${WEBTERM_BACKUP_DIR:-$(PWD)/backups}" ./scripts/backup.sh

backup-install: ## Install the daily systemd backup timer (needs sudo)
	sudo cp deploy/webterm-backup.service deploy/webterm-backup.timer /etc/systemd/system/
	sudo sed -i "s#/opt/webterm#$(PWD)#g" /etc/systemd/system/webterm-backup.service
	sudo systemctl daemon-reload && sudo systemctl enable --now webterm-backup.timer
	@echo "Daily backup active. Check: systemctl list-timers webterm-backup.timer"

test: ## Run the hermetic suite — exactly what CI gates the image on (needs .venv)
	PY=./.venv/bin/python scripts/run-tests.sh ci

test-local: ## test + the suites that need real tmux/agent (sandboxed from production)
	PY=./.venv/bin/python scripts/run-tests.sh all

build: ## Build frontend + image
	cd frontend && npm ci && npm run build && cd .. && $(COMPOSE) build
