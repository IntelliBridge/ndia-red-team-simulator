SHELL := /bin/bash

# `up` runs compose through scripts/with-session-keypair.sh: it generates the
# API session keypair (deploy/certs/redsim-api-session.{key,pub}, gitignored)
# on the first run and exports both halves, so redsim-web can mint the
# redsim_api_session cookie and redsim-api can verify it. `rebuild` goes
# through the same wrapper because recreating a container without the two
# variables would leave it with empty keys.
up:
	scripts/with-session-keypair.sh docker compose up -d --build

up-obs:
	scripts/with-session-keypair.sh docker compose --profile obs up -d --build

# The organisation and project rows only, through the same script the Fargate
# runtime runs (deploy/runtime/scripts/seed_project.py, fed on stdin). No User
# or ProjectMembership row: the API reads memberships from the
# redsim_project_roles token claim, which the realm export gives the admin
# user as {"default": "admin"}. A rerun reports the rows as present.
seed:
	docker compose exec -T redsim-api python - default-org default Default < runtime/scripts/seed_project.py

token-for:
	@echo "dev:$$(basename $@)"

whoami:
	curl -s http://localhost:8000/health | jq .

psql:
	docker compose exec postgres psql -U redsim -d redsim

logs:
	docker compose logs -f --tail=200 $$svc

rebuild:
	docker compose build $$svc && scripts/with-session-keypair.sh docker compose up -d $$svc

down:
	docker compose down

down-clean:
	docker compose down -v

.PHONY: up up-obs seed token-for whoami psql logs rebuild down down-clean
