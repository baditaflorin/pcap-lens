VERSION := $(shell node -p "require('./package.json').version")

.PHONY: help install-hooks dev build data test test-integration smoke lint fmt pages-preview docker-build docker-push release compose-up compose-down clean hooks-pre-commit hooks-commit-msg hooks-pre-push

help:
	@echo "Targets:"
	@echo "  make install-hooks     Wire .githooks"
	@echo "  make dev               Run frontend dev server"
	@echo "  make build             Build Pages-ready frontend into docs/"
	@echo "  make data              No-op for Mode A"
	@echo "  make test              Run unit tests"
	@echo "  make test-integration  No-op for Mode A"
	@echo "  make smoke             Build, serve docs, and run Playwright"
	@echo "  make lint              Run eslint, prettier, and audit checks"
	@echo "  make fmt               Autoformat"
	@echo "  make pages-preview     Serve the production build locally"
	@echo "  make release           Tag v$(VERSION)"
	@echo "  make clean             Remove local generated artifacts"

install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*

dev:
	npm run dev

build:
	npm run build

data:
	@echo "Mode A has no static data-generation pipeline."

test:
	npm run test

test-integration:
	@echo "No separate integration suite for Mode A v1."

smoke:
	npm run smoke

lint:
	npm run lint
	npm audit --audit-level=high

fmt:
	npm run fmt

pages-preview:
	npm run build
	npx vite preview --host 127.0.0.1 --port 4173

docker-build:
	@echo "Mode A does not build Docker images."

docker-push:
	@echo "Mode A does not push Docker images."

release:
	git tag "v$(VERSION)"
	git push origin "v$(VERSION)"

compose-up:
	@echo "Mode A has no Docker Compose stack."

compose-down:
	@echo "Mode A has no Docker Compose stack."

clean:
	rm -rf coverage test-results playwright-report node_modules/.tmp

hooks-pre-commit:
	.githooks/pre-commit

hooks-commit-msg:
	.githooks/commit-msg $${COMMIT_MSG_FILE:-.git/COMMIT_EDITMSG}

hooks-pre-push:
	.githooks/pre-push
