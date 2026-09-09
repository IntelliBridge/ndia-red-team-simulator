#!/usr/bin/env python3
"""Configure the live Keycloak realm for redsim, idempotently.

Three things, each skipped when already present:

1. The ``redsim_project_roles`` User Attribute protocol mapper on the
   ``redsim-web`` client (ID token, access token and userinfo, claim JSON type
   ``JSON``). ``--import-realm`` skips an existing realm, so the mapper that
   ``identity/realm.json`` declares has to be added to the live realm once.
2. The ``redsim_project_roles`` user-profile attribute, view and edit limited
   to administrators.
3. Optionally (``--cli-client redsim-cli``) a public direct-grant client whose
   access tokens carry the ``redsim`` audience, for bearer access from the
   CLI and ``scripts/smoke_live.sh``.
4. The demo users named in ``--users`` (a JSON file: a list of
   ``{"username", "email", "first_name", "last_name", "memberships": {"<project_id>": "<role>"}}``),
   each with the memberships object stored as the single value of the
   ``redsim_project_roles`` attribute and a generated password.

Passwords are generated here, written to the Secrets Manager secret named by
``--users-secret`` as a JSON object ``{username: password}`` and never printed.
On a rerun an existing entry is reused, so the script is a no-op the second
time. The Keycloak bootstrap administrator credential is read from the
``KC_BOOTSTRAP_ADMIN_PASSWORD`` field of ``--identity-secret``.

Requires boto3. TLS verification uses the default context, so set
``SSL_CERT_FILE`` behind an inspecting proxy.
"""
import argparse
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

import boto3

ROLES = {"viewer", "scanner", "remediator", "approver", "admin"}
CLAIM = "redsim_project_roles"


class Keycloak:
    def __init__(self, base_url: str, realm: str, token: str, context: ssl.SSLContext) -> None:
        self.base = f"{base_url.rstrip('/')}/admin/realms/{realm}"
        self.token = token
        self.context = context

    def call(self, method: str, path: str, body: object = None) -> object:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"{self.base}{path}", data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{method} {path}: HTTP {exc.code} {exc.read()[:300]!r}") from exc
        return json.loads(raw) if raw else None


def admin_token(base_url: str, username: str, password: str, context: ssl.SSLContext) -> str:
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                   "username": username, "password": password}).encode()
    request = urllib.request.Request(f"{base_url.rstrip('/')}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(request, context=context, timeout=60) as response:
        return str(json.load(response)["access_token"])


def ensure_mapper(kc: Keycloak, client_id: str) -> str:
    clients = kc.call("GET", f"/clients?clientId={urllib.parse.quote(client_id)}")
    if not clients:
        raise RuntimeError(f"client {client_id} not found in the realm")
    internal = clients[0]["id"]
    mappers = kc.call("GET", f"/clients/{internal}/protocol-mappers/models") or []
    if any(m.get("name") == CLAIM for m in mappers):
        return "present"
    kc.call("POST", f"/clients/{internal}/protocol-mappers/models", {
        "name": CLAIM, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {"user.attribute": CLAIM, "claim.name": CLAIM, "jsonType.label": "JSON",
                   "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
                   "multivalued": "false", "aggregate.attrs": "false"}})
    return "created"


def ensure_profile_attribute(kc: Keycloak) -> str:
    profile = kc.call("GET", "/users/profile")
    attributes = profile.setdefault("attributes", [])
    if any(a.get("name") == CLAIM for a in attributes):
        return "present"
    attributes.append({"name": CLAIM, "displayName": "Project memberships (redsim_project_roles)",
                       "permissions": {"view": ["admin"], "edit": ["admin"]}, "multivalued": False})
    kc.call("PUT", "/users/profile", profile)
    return "created"


def ensure_cli_client(kc: Keycloak, client_id: str, audience: str) -> str:
    """A public client for bearer-token access from the CLI and the live smoke.

    Direct access grants only (no browser flow), the same ``redsim_project_roles``
    mapper as the web client, and an audience mapper adding ``audience`` (the
    API's ``REDSIM_OIDC_AUDIENCE``, default ``redsim``) so the API accepts the
    access token. Public clients hold no secret; the user's password is still
    required to obtain a token.
    """
    found = kc.call("GET", f"/clients?clientId={urllib.parse.quote(client_id)}") or []
    if found:
        return "present"
    kc.call("POST", "/clients", {
        "clientId": client_id, "name": "redsim CLI (bearer tokens)", "protocol": "openid-connect",
        "publicClient": True, "directAccessGrantsEnabled": True, "standardFlowEnabled": False,
        "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "enabled": True,
        "protocolMappers": [
            {"name": CLAIM, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
             "consentRequired": False,
             "config": {"user.attribute": CLAIM, "claim.name": CLAIM, "jsonType.label": "JSON",
                        "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
                        "multivalued": "false", "aggregate.attrs": "false"}},
            {"name": f"audience-{audience}", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
             "consentRequired": False,
             "config": {"included.custom.audience": audience, "id.token.claim": "false",
                        "access.token.claim": "true"}},
        ]})
    return "created"


def ensure_user(kc: Keycloak, spec: dict, password: str | None) -> tuple[str, str | None]:
    memberships = spec.get("memberships") or {}
    bad = {p: r for p, r in memberships.items() if r not in ROLES}
    if bad:
        raise RuntimeError(f"{spec['username']}: unknown roles {bad}")
    claim_value = json.dumps(memberships, separators=(",", ":"), sort_keys=True)
    found = kc.call("GET", f"/users?username={urllib.parse.quote(spec['username'])}&exact=true") or []
    representation = {"username": spec["username"], "email": spec["email"], "enabled": True,
                      "emailVerified": True, "firstName": spec.get("first_name", ""),
                      "lastName": spec.get("last_name", ""), "attributes": {CLAIM: [claim_value]}}
    if found:
        user = found[0]
        current = (user.get("attributes") or {}).get(CLAIM) or []
        if current == [claim_value] and user.get("enabled"):
            return "present", None
        kc.call("PUT", f"/users/{user['id']}", {**user, **representation})
        return "updated", None
    kc.call("POST", "/users", representation)
    created = kc.call("GET", f"/users?username={urllib.parse.quote(spec['username'])}&exact=true")[0]
    new_password = password or secrets.token_urlsafe(24)
    kc.call("PUT", f"/users/{created['id']}/reset-password",
            {"type": "password", "value": new_password, "temporary": False})
    return "created", new_password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://redsim.ndia.agiledefense.xyz/auth")
    parser.add_argument("--realm", default="redsim")
    parser.add_argument("--client-id", default="redsim-web")
    parser.add_argument("--identity-secret", default="ndia-red-team/demo/identity")
    parser.add_argument("--users-secret", default="ndia-red-team/demo/demo-users")
    parser.add_argument("--users", help="JSON file with the demo users; omit to configure the realm only")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--cli-client", metavar="CLIENT_ID", default=None,
                        help="also create a public direct-grant client of this id for bearer tokens (e.g. redsim-cli)")
    parser.add_argument("--audience", default="redsim", help="API audience the CLI client's tokens carry (REDSIM_OIDC_AUDIENCE)")
    args = parser.parse_args()

    context = ssl.create_default_context()
    sm = boto3.client("secretsmanager", region_name=args.region)
    identity = json.loads(sm.get_secret_value(SecretId=args.identity_secret)["SecretString"])
    token = admin_token(args.base_url, identity.get("KC_BOOTSTRAP_ADMIN_USERNAME", "redsim-admin"),
                        identity["KC_BOOTSTRAP_ADMIN_PASSWORD"], context)
    kc = Keycloak(args.base_url, args.realm, token, context)

    print(f"mapper {CLAIM} on {args.client_id}: {ensure_mapper(kc, args.client_id)}")
    print(f"user-profile attribute {CLAIM}: {ensure_profile_attribute(kc)}")
    if args.cli_client:
        print(f"CLI client {args.cli_client} (audience {args.audience}): {ensure_cli_client(kc, args.cli_client, args.audience)}")
    if not args.users:
        return 0

    with open(args.users, encoding="utf-8") as handle:
        users = json.load(handle)
    try:
        stored = json.loads(sm.get_secret_value(SecretId=args.users_secret)["SecretString"])
        secret_exists = True
    except sm.exceptions.ResourceNotFoundException:
        stored, secret_exists = {}, False
    changed = False
    for spec in users:
        outcome, password = ensure_user(kc, spec, stored.get(spec["username"]))
        print(f"user {spec['username']} {json.dumps(spec.get('memberships') or {}, sort_keys=True)}: {outcome}")
        if password is not None and stored.get(spec["username"]) != password:
            stored[spec["username"]] = password
            changed = True
    if changed:
        payload = json.dumps(stored)
        if secret_exists:
            sm.put_secret_value(SecretId=args.users_secret, SecretString=payload)
        else:
            sm.create_secret(Name=args.users_secret, SecretString=payload,
                             Description="redsim demo user passwords (generated by seed_identity.py)")
        print(f"passwords stored in Secrets Manager {args.users_secret} (never printed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
