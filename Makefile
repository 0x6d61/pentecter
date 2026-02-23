COMPOSE := docker compose -f demo/docker-compose.yml

.PHONY: demo demo-down demo-build e2e

## demo: build all images and run pentecter (interactive)
demo:
	$(COMPOSE) down --remove-orphans 2>/dev/null || true
	$(COMPOSE) build
	$(COMPOSE) run --rm pentecter

## demo-down: stop and remove all demo containers
demo-down:
	$(COMPOSE) down --remove-orphans

## demo-build: build all demo images without starting
demo-build:
	$(COMPOSE) build

## e2e: start targets, run E2E tests, then stop
e2e:
	$(COMPOSE) down --remove-orphans 2>/dev/null || true
	$(COMPOSE) up -d target vulnboard
	$(COMPOSE) exec target sh -c 'until netstat -tlnp | grep :80; do sleep 2; done'
	go test -v -tags=e2e -timeout 300s ./e2e/...
	$(COMPOSE) down
