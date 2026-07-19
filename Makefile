# Provx — developer task shortcuts. Run `make help` to list targets.
# Thin wrappers over docker compose and per-service tooling. TODO markers show where
# real commands land as features arrive.

COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help up down build rebuild logs ps restart lint fmt test clean env

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

lint: ## Lint all code
	@echo "TODO backend: cd backend && ruff check . && ruff format --check ."
	@echo "TODO frontend: cd frontend && npm run lint"

fmt: ## Auto-format all code
	@echo "TODO backend: cd backend && ruff format ."
	@echo "TODO frontend: cd frontend && npx prettier --write ."

test: ## Run unit + fixture tests
	@echo "TODO backend: cd backend && pytest"

clean: ## Remove containers, volumes, and build artifacts
	$(COMPOSE) down -v --remove-orphans
