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

# The development seed (redsim/db/seed.py): default-org, project default and
# the admin user twice, once per sign-in path (the Keycloak subject the realm
# export pins on its admin user, and dev:admin@redsim.local for a dev bearer
# token), each with an admin membership on the project. redsim-api runs it
# on every start after the migration, so this target is for a stack whose
# rows were dropped by hand. A rerun prints "nothing new".
seed:
	docker compose exec -T redsim-api python -m redsim.db.seed

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
