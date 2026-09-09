from pathlib import Path
import re
import unittest

DOCKERFILE = Path(__file__).parents[2] / 'Dockerfile.web'
COMPOSE = Path(__file__).parents[2] / 'docker-compose.yml'


class WebDockerfileTests(unittest.TestCase):
    """The browser API origin is a required build argument (brief E9)."""

    def test_no_localhost_default(self):
        text = DOCKERFILE.read_text()
        arg = re.search(r'^ARG NEXT_PUBLIC_REDSIM_API_URL(=.*)?$', text, re.M)
        self.assertIsNotNone(arg, 'the web Dockerfile declares the build argument')
        self.assertIsNone(arg.group(1), 'the build argument has no default, so no image can carry localhost by accident')
        self.assertIn('test -n "${NEXT_PUBLIC_REDSIM_API_URL}"', text, 'the build fails with a message when the argument is missing')

    def test_compose_passes_the_argument_explicitly(self):
        text = COMPOSE.read_text()
        self.assertRegex(text, r'args:\s+NEXT_PUBLIC_REDSIM_API_URL: http://localhost:8000',
                         'the local stack passes its own origin as a build argument')


if __name__ == '__main__':
    unittest.main()
