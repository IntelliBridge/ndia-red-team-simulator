#!/usr/bin/env python3
"""Wire connection secrets after foundation apply; emit ARN references only."""
import argparse
import json
from pathlib import Path
from urllib.parse import quote

from prepare_secrets import RETIRED_SECRET_KEYS, aws, save_secret

parser = argparse.ArgumentParser()
parser.add_argument('--foundation-outputs', type=Path, required=True)
parser.add_argument('--environment', default='demo')
args = parser.parse_args()
outputs = {key: value['value'] for key, value in json.loads(args.foundation_outputs.read_text()).items()}
connections = outputs['data_connections']
prefix = f'ndia-red-team/{args.environment}'
bootstrap = json.loads(aws('secretsmanager', 'get-secret-value', {'SecretId': f'{prefix}/bootstrap'})['SecretString'])
host = connections['database']['host']
redis = connections['redis']['primary_endpoint']
db_url = f"postgresql+psycopg://redsim_app:{quote(bootstrap['app_password'], safe='')}@{host}:5432/redsim?sslmode=require"
redis_url = f"rediss://redsim:{quote(bootstrap['redis_password'], safe='')}@{redis}:6379"
references = {}
for service in ['api', 'web', 'scans', 'default', 'beat', 'migration', 'assets', 'identity']:
    current = aws('secretsmanager', 'get-secret-value', {'SecretId': f'{prefix}/{service}'})
    values = json.loads(current['SecretString'])
    if service in ['api', 'scans', 'default', 'beat', 'assets']:
        values['REDSIM_DB_URL'] = db_url
    if service in ['api', 'scans', 'default', 'beat']:
        # Celery's Redis transport reads TLS verification from URL query options.
        values['REDSIM_BROKER_URL'] = redis_url + '/0?ssl_cert_reqs=required'
        values['REDSIM_RESULT_BACKEND'] = redis_url + '/1?ssl_cert_reqs=required'
    arn = save_secret(f'{prefix}/{service}', values)
    # Retired names stay in the secret so an already-registered task definition
    # can still resolve them, and are left out here so the task definitions
    # this run produces reference the replacement alone.
    references[service] = {key: f'{arn}:{key}::' for key in values
                           if key not in RETIRED_SECRET_KEYS}
master = connections['database']['managed_master_secret_arn']
references['migration']['REDSIM_DB_ADMIN_USERNAME'] = f'{master}:username::'
references['migration']['REDSIM_DB_ADMIN_PASSWORD'] = f'{master}:password::'
print(json.dumps(references, indent=2))
