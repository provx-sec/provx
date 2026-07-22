# Provx - developer task shortcuts. Run `make help` to list targets.
# Thin wrappers over docker compose and per-service tooling.

COMPOSE ?= docker compose
# Prefer the repo venv when it exists so `make test` works without activating it.
PY ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
PY_SOURCES := backend packages/adapters lab

.DEFAULT_GOAL := help
.PHONY: help up down build rebuild logs ps restart lint fmt test accuracy clean env

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example")

up: env ## Build (if needed) and start all services
	$(COMPOSE) up --build

down: ## Stop and remove containers
	$(COMPOSE) down

build: ## Build all service images
	$(COMPOSE) build

rebuild: ## Rebuild images from scratch (no cache)
	$(COMPOSE) build --no-cache

logs: ## Tail logs from all services
	$(COMPOSE) logs -f

ps: ## Show running services
	$(COMPOSE) ps

restart: down up ## Restart the stack

lint: ## Lint and type-check all code
	$(PY) -m ruff check $(PY_SOURCES)
	$(PY) -m ruff format --check $(PY_SOURCES)
	$(PY) -m mypy backend/app packages/adapters/src/provx_sdk lab
	cd frontend && npm run lint && npm run typecheck

fmt: ## Auto-format all code
	$(PY) -m ruff format $(PY_SOURCES)
	$(PY) -m ruff check --fix $(PY_SOURCES)

test: ## Run unit + fixture tests
	APP_ENV=testing $(PY) -m pytest -q

accuracy: ## Score the deterministic checks against the lab targets (TP/FP/FN gate)
	# --build is not optional: a stale image scores yesterday's code and the gate passes
	# without having tested anything. Each adapter scores only the targets it owns, so the
	# gate runs once per adapter and fails if either run does.
	$(COMPOSE) --profile lab build accuracy
	$(COMPOSE) --profile lab up -d \
		lab-missing-headers lab-hardened lab-tls-insecure lab-tls-secure \
		lab-cookies-insecure lab-cookies-secure lab-cors-wildcard lab-cors-safe \
		lab-wellknown-missing lab-wellknown-present
	@status=0; \
		$(COMPOSE) --profile lab run --rm accuracy --adapter security_headers || status=1; \
		$(COMPOSE) --profile lab run --rm accuracy --adapter tls || status=1; \
		$(COMPOSE) --profile lab run --rm accuracy --adapter cookie_flags || status=1; \
		$(COMPOSE) --profile lab run --rm accuracy --adapter cors || status=1; \
		$(COMPOSE) --profile lab run --rm accuracy --adapter wellknown || status=1; \
		$(COMPOSE) --profile lab down; \
		exit $$status

clean: ## Remove containers, volumes, and build artifacts
	$(COMPOSE) down -v --remove-orphans
