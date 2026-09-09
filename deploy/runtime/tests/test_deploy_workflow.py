import shutil
import subprocess
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # the README's ``uv run --no-project`` invocation has no PyYAML
    yaml = None

WORKFLOW = Path(__file__).parents[3] / '.github/workflows/deploy-aws.yml'
GUARD_NAME = 'Require an https NEXT_PUBLIC_REDSIM_API_URL'
BUILD_ARG = 'NEXT_PUBLIC_REDSIM_API_URL=${{ vars.NEXT_PUBLIC_REDSIM_API_URL }}'


class DeployWorkflowTextTests(unittest.TestCase):
    """Text-level checks that run without PyYAML."""

    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_web_build_arg_has_no_localhost_fallback(self):
        arg_lines = [line.strip() for line in self.text.splitlines() if 'NEXT_PUBLIC_REDSIM_API_URL=${{' in line]
        self.assertEqual(arg_lines, [BUILD_ARG])
        self.assertNotIn('http://localhost', self.text)
        self.assertNotIn("|| 'http", self.text)

    def test_guard_step_is_present(self):
        self.assertIn(GUARD_NAME, self.text)
        self.assertLess(self.text.index(GUARD_NAME), self.text.index('Configure AWS credentials'))


@unittest.skipIf(yaml is None, 'PyYAML is not installed')
class DeployWorkflowStructureTests(unittest.TestCase):
    def setUp(self):
        self.steps = yaml.safe_load(WORKFLOW.read_text())['jobs']['build-and-push']['steps']
        self.names = [step.get('name', step.get('uses', '')) for step in self.steps]
        self.guard = self.steps[self.index(GUARD_NAME)]

    def index(self, prefix):
        return next(i for i, name in enumerate(self.names) if name.startswith(prefix))

    def test_guard_runs_first_and_only_for_web(self):
        self.assertEqual(self.index(GUARD_NAME), 0)
        self.assertLess(self.index(GUARD_NAME), self.index('Configure AWS credentials'))
        self.assertLess(self.index(GUARD_NAME), self.index('Build and push'))
        self.assertEqual(self.guard['if'], "matrix.name == 'web'")
        self.assertEqual(self.guard['env'], {'NEXT_PUBLIC_REDSIM_API_URL': '${{ vars.NEXT_PUBLIC_REDSIM_API_URL }}'})

    def test_build_arg_is_passed_verbatim(self):
        build = self.steps[self.index('Build and push')]
        self.assertEqual(build['with']['build-args'].strip(), BUILD_ARG)

    @unittest.skipIf(shutil.which('bash') is None, 'bash is not installed')
    def test_guard_script_rejects_missing_http_and_loopback_values(self):
        rejected = ['', 'http://localhost:8000', 'http://redsim.example.test', 'https://localhost:8000',
                    'https://127.0.0.1:8000', 'https://[::1]:8000', 'https://', 'redsim.example.test']
        accepted = ['https://redsim.example.test', 'https://redsim.example.test:8443/api']
        for value, expected in [(v, 1) for v in rejected] + [(v, 0) for v in accepted]:
            with self.subTest(value=value):
                proc = subprocess.run(
                    ['bash', '-c', self.guard['run']],
                    env={'NEXT_PUBLIC_REDSIM_API_URL': value, 'PATH': '/usr/bin:/bin'},
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
                if expected:
                    self.assertIn('::error::', proc.stderr)


if __name__ == '__main__':
    unittest.main()
