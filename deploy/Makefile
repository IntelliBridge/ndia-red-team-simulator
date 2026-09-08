SHELL := /bin/bash

up:
	docker compose up -d --build

up-obs:
	docker compose --profile obs up -d --build

seed:
	docker compose exec aegis-api python - <<'PY'
	from aegis.db.models import Organization, Project, User, ProjectMembership
	from aegis.db.session import get_session, init_engine
	import os
	init_engine(os.environ['AEGIS_DB_URL'])
	with get_session() as s:
	    if not s.get(Organization, 'default-org'):
	        s.add(Organization(id='default-org', name='Default', slug='default'))
	    if not s.get(Project, 'default'):
	        s.add(Project(id='default', org_id='default-org', name='Default', slug='default'))
	    if not s.get(User, 'admin'):
	        s.add(User(id='admin', sub='admin@aegis.local', email='admin@aegis.local'))
	        s.add(ProjectMembership(user_id='admin', project_id='default', role='admin'))
	    print('seeded')
	PY

token-for:
	@echo "dev:$$(basename $@)"

whoami:
	curl -s http://localhost:8000/health | jq .

psql:
	docker compose exec postgres psql -U aegis -d aegis

logs:
	docker compose logs -f --tail=200 $$svc

rebuild:
	docker compose build $$svc && docker compose up -d $$svc

down:
	docker compose down

down-clean:
	docker compose down -v

.PHONY: up up-obs seed token-for whoami psql logs rebuild down down-clean
