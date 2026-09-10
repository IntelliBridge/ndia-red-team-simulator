SHELL := /bin/bash

up:
	docker compose up -d --build

up-obs:
	docker compose --profile obs up -d --build

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
	docker compose build $$svc && docker compose up -d $$svc

down:
	docker compose down

down-clean:
	docker compose down -v

.PHONY: up up-obs seed token-for whoami psql logs rebuild down down-clean
