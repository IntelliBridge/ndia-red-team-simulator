from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))

from prepare_secrets import RETIRED_SECRET_KEYS  # noqa: E402


class RetiredSecretKeyTests(unittest.TestCase):
    """A retired key leaves the task definition before it leaves the secret.

    configure_connections.py parses argv at import, so it cannot be imported
    and driven here. These read its source instead, the way
    test_web_dockerfile.py reads the Dockerfile. What they pin is an ordering
    invariant rather than a formatting one: dropping a key from the secret
    while a registered task definition still names it strands any task placed
    before the apply that re-registers it.
    """

    def test_the_retired_list_is_declared_once(self):
        self.assertIn('NEXTAUTH_SECRET', RETIRED_SECRET_KEYS)
        text = (SCRIPTS / 'configure_connections.py').read_text()
        self.assertIn('from prepare_secrets import RETIRED_SECRET_KEYS', text,
                      'the reference builder imports the list rather than keeping a copy')

    def test_prepare_secrets_keeps_a_retired_key_in_the_secret(self):
        text = (SCRIPTS / 'prepare_secrets.py').read_text()
        self.assertNotIn('merged.pop(', text,
                         'the merged secret keeps retired keys, so an already-registered '
                         'task definition can still resolve them')

    def test_configure_connections_keeps_a_retired_key_out_of_the_references(self):
        text = (SCRIPTS / 'configure_connections.py').read_text()
        self.assertIn('if key not in RETIRED_SECRET_KEYS', text,
                      'the emitted valueFrom references carry the replacement alone')

    def test_the_exclusion_applies_to_the_reference_comprehension(self):
        # The same comprehension the script runs, over a secret that still
        # carries the retired name beside its replacement.
        arn = 'arn:aws:secretsmanager:us-east-1:000000000000:secret:ndia-red-team/demo/web-AbCdEf'
        values = {'NEXTAUTH_SECRET': 'x', 'BETTER_AUTH_SECRET': 'y'}
        references = {key: f'{arn}:{key}::' for key in values
                      if key not in RETIRED_SECRET_KEYS}
        self.assertEqual(list(references), ['BETTER_AUTH_SECRET'])


if __name__ == '__main__':
    unittest.main()
