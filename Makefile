SHELL := /bin/bash

.PHONY: up up-demo down logs ps demo verify test lint audit compose-check

up:
	./scripts/up.sh

up-demo:
	./scripts/up.sh --demo

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

ps:
	docker compose ps

demo:
	python3 scripts/demo-flows.py --once

verify:
	./scripts/verify-stack.sh

compose-check:
	docker compose --env-file .env.example config -q

test:
	pytest -v

lint:
	ruff check src tests scripts .github/scripts

audit:
	python3 scripts/zero_pii_audit.py
