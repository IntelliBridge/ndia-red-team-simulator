import json
import unittest
from pathlib import Path

RUNTIME = Path(__file__).parents[1]
REALM = RUNTIME / 'identity/realm.json'
README = RUNTIME / 'README.md'
CLAIM = 'redsim_project_roles'
DEFAULT_PROFILE_ATTRIBUTES = ('username', 'email', 'firstName', 'lastName')


class RealmProjectRolesClaimTests(unittest.TestCase):
    """The app authorises from the ``redsim_project_roles`` claim, so the realm must emit it."""

    def setUp(self):
        self.realm = json.loads(REALM.read_text())
        self.client = next(c for c in self.realm['clients'] if c['clientId'] == 'redsim-web')

    def mapper(self):
        mappers = [m for m in self.client.get('protocolMappers', []) if m.get('config', {}).get('claim.name') == CLAIM]
        self.assertEqual(len(mappers), 1, 'exactly one mapper on redsim-web must emit the claim')
        return mappers[0]

    def test_web_client_carries_user_attribute_mapper_for_claim(self):
        mapper = self.mapper()
        self.assertEqual(mapper['protocol'], 'openid-connect')
        self.assertEqual(mapper['protocolMapper'], 'oidc-usermodel-attribute-mapper')
        self.assertFalse(mapper.get('consentRequired', False))
        config = mapper['config']
        self.assertEqual(config['user.attribute'], CLAIM)
        self.assertEqual(config['claim.name'], CLAIM)
        self.assertEqual(config['jsonType.label'], 'JSON', 'the attribute holds a JSON object, not a string')
        self.assertEqual(config.get('multivalued', 'false'), 'false', 'one JSON object per user, not a list')

    def test_claim_reaches_id_token_access_token_and_userinfo(self):
        config = self.mapper()['config']
        for target in ('id.token.claim', 'access.token.claim', 'userinfo.token.claim'):
            with self.subTest(target=target):
                self.assertEqual(config[target], 'true')

    def test_mapper_is_on_the_client_and_default_scopes_are_untouched(self):
        # A mapper defined on the client belongs to its dedicated scope and is applied to every
        # token issued to that client. Listing clientScopes/defaultClientScopes during import would
        # replace Keycloak's built-in defaults (profile, email, roles, ...), so they must stay absent.
        self.assertIn('protocolMappers', self.client)
        self.assertNotIn('clientScopes', self.realm)
        self.assertNotIn('defaultDefaultClientScopes', self.realm)
        self.assertNotIn('defaultClientScopes', self.client)

    def test_membership_attribute_is_declared_and_admin_only(self):
        components = self.realm['components']['org.keycloak.userprofile.UserProfileProvider']
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]['providerId'], 'declarative-user-profile')
        profile = json.loads(components[0]['config']['kc.user.profile.config'][0])
        names = [attribute['name'] for attribute in profile['attributes']]
        for required in DEFAULT_PROFILE_ATTRIBUTES + (CLAIM,):
            with self.subTest(attribute=required):
                self.assertIn(required, names)
        attribute = next(a for a in profile['attributes'] if a['name'] == CLAIM)
        self.assertEqual(attribute['permissions'], {'view': ['admin'], 'edit': ['admin']},
                         'users must not be able to grant themselves memberships')
        self.assertFalse(attribute.get('multivalued', False))
        self.assertNotIn('unmanagedAttributePolicy', profile)

    def test_realm_still_has_no_users_and_keeps_injected_placeholders(self):
        self.assertNotIn('users', self.realm)
        self.assertEqual(self.client['secret'], '${REDSIM_WEB_CLIENT_SECRET}')
        self.assertFalse(self.client['publicClient'])
        self.assertFalse(self.client['directAccessGrantsEnabled'])


class ReadmeMembershipDocumentationTests(unittest.TestCase):
    def test_readme_documents_attribute_shape_and_live_realm_update(self):
        text = README.read_text()
        self.assertIn('## Project membership claim', text)
        self.assertIn('`redsim_project_roles`', text)
        self.assertIn('{"<project_id>": "approver"}', text)
        self.assertIn('--import-realm', text)
        self.assertIn('redsim-web-dedicated', text)


if __name__ == '__main__':
    unittest.main()
