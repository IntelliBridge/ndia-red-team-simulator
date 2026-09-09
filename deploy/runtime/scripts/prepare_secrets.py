#!/usr/bin/env python3
"""Prepare external runtime credentials without storing values in Terraform.

Use AWS_PROFILE for an operator identity. Secret values travel through the AWS SDK in memory, never argv or logs. Existing bootstrap credentials are reused on subsequent runs.
Only identifiers are printed. This does not rotate existing credentials.
"""
import argparse
import base64
import json
import secrets
import subprocess


def aws(service, operation, payload=None):
    import boto3
    from botocore.exceptions import ClientError
    try:
        return getattr(boto3.client(service, region_name='us-east-1'), operation.replace('-', '_'))(**(payload or {}))
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        raise RuntimeError(f"AWS {service} {operation} failed: {exc.response['Error']['Code']}") from None


def save_secret(name, value):
    existing = aws('secretsmanager', 'describe-secret', {'SecretId': name})
    if existing:
        return aws('secretsmanager', 'put-secret-value', {
            'SecretId': name, 'SecretString': json.dumps(value)})['ARN']
    return aws('secretsmanager', 'create-secret', {
        'Name': name, 'SecretString': json.dumps(value),
        'Tags': [{'Key': 'Application', 'Value': 'redsim'}]})['ARN']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--environment', default='demo')
    args = parser.parse_args()
    prefix = f'ndia-red-team/{args.environment}'
    seed = aws('secretsmanager', 'get-secret-value', {'SecretId': f'{prefix}/bootstrap'})
    if seed:
        values = json.loads(seed['SecretString'])
    else:
        private = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'RSA',
            '-pkeyopt', 'rsa_keygen_bits:3072'], stderr=subprocess.DEVNULL)
        public = subprocess.check_output(['openssl', 'pkey', '-pubout'], input=private)
        values = {
            'app_password': secrets.token_hex(32), 'identity_password': secrets.token_hex(32),
            'redis_password': secrets.token_hex(32), 'worker_signing_key': secrets.token_hex(32),
            'auth_profiles_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            'nextauth_secret': secrets.token_hex(32), 'keycloak_client_secret': secrets.token_hex(32),
            'keycloak_admin_password': secrets.token_hex(32),
            'session_private_key': private.decode(), 'session_public_key': public.decode(),
        }
        save_secret(f'{prefix}/bootstrap', values)
    shared = {'REDSIM_WORKER_SIGNING_KEY': values['worker_signing_key'],
              'REDSIM_AUTH_PROFILES_KEY': values['auth_profiles_key']}
    services = {name: dict(shared) for name in ['api', 'scans', 'default', 'beat', 'assets']}
    services['api']['REDSIM_API_SESSION_PUBLIC_KEY'] = values['session_public_key']
    # BETTER_AUTH_SECRET, not NEXTAUTH_SECRET: the T3 refactor replaced NextAuth
    # with Better Auth and web/src/env.js requires the new name at boot.
    # configure_connections.py derives the var.service_secrets references from
    # this dict's keys, so renaming here renames the task definition reference.
    # The bootstrap key keeping its old name is deliberate: it is read back on
    # every rerun, and renaming it would mint a fresh secret and sign every
    # live browser session out.
    services['web'] = {'BETTER_AUTH_SECRET': values['nextauth_secret'],
        'KEYCLOAK_CLIENT_SECRET': values['keycloak_client_secret'],
        'REDSIM_API_SESSION_PRIVATE_KEY': values['session_private_key']}
    services['identity'] = {'KC_DB_PASSWORD': values['identity_password'],
        'KC_BOOTSTRAP_ADMIN_PASSWORD': values['keycloak_admin_password'],
        'REDSIM_WEB_CLIENT_SECRET': values['keycloak_client_secret']}
    services['migration'] = {'REDSIM_APP_DB_PASSWORD': values['app_password'],
                             'REDSIM_IDENTITY_DB_PASSWORD': values['identity_password']}
    references = {}
    for service, value in services.items():
        # Preserve derived connection URLs on reruns.
        current = aws('secretsmanager', 'get-secret-value', {'SecretId': f'{prefix}/{service}'})
        merged = json.loads(current['SecretString']) if current else {}
        merged.update(value)
        references[service] = save_secret(f'{prefix}/{service}', merged)
    group_id = f'ndia-red-team-{args.environment}'
    current = aws('elasticache', 'describe-user-groups', {})['UserGroups']
    if not any(group['UserGroupId'] == group_id for group in current):
        users = aws('elasticache', 'describe-users', {})['Users']
        existing_ids = {user['UserId'] for user in users}
        disabled_id = f'{group_id}-disabled'
        app_id = f'{group_id}-app'
        if disabled_id not in existing_ids:
            aws('elasticache', 'create-user', {'UserId': disabled_id, 'UserName': 'default',
                'Engine': 'REDIS', 'AccessString': 'off ~* -@all', 'NoPasswordRequired': True})
        if app_id not in existing_ids:
            aws('elasticache', 'create-user', {'UserId': app_id, 'UserName': 'redsim',
                'Engine': 'REDIS', 'AccessString': 'on ~* +@all', 'Passwords': [values['redis_password']]})
        aws('elasticache', 'create-user-group', {'UserGroupId': group_id, 'Engine': 'REDIS',
                                               'UserIds': [disabled_id, app_id]})
    print(json.dumps({'runtime_secret_arns': {k: [v] for k, v in references.items()},
                      'redis_user_group_id': group_id}, indent=2))


if __name__ == '__main__':
    main()
