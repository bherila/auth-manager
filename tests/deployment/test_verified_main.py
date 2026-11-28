import copy
import datetime as dt
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('verified_main', ROOT / 'scripts/release/verified-main.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SHA = 'a' * 40
NOW = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)


class VerifiedMainTest(unittest.TestCase):
    def setUp(self):
        self.run = {'id': 101, 'run_attempt': 2, 'workflow_id': 51,
                    'path': MODULE.WORKFLOW, 'event': 'push', 'head_branch': 'main',
                    'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
                    'run_started_at': '2026-01-01T22:00:00Z',
                    'updated_at': '2026-01-01T23:00:00Z',
                    'repository': {'full_name': MODULE.REPOSITORY},
                    'head_repository': {'full_name': MODULE.REPOSITORY}}
        self.jobs = [{'name': name, 'run_id': 101, 'run_attempt': 2,
                      'head_sha': SHA, 'status': 'completed', 'conclusion': 'success'}
                     for name in sorted(MODULE.REQUIRED_JOBS)]
        self.calls = []
        self.final = None
        self.partial_runs = False
        self.partial_jobs = False
        self.workflow = {'id': 51, 'path': MODULE.WORKFLOW}

    def fetch(self, path):
        self.calls.append(path)
        if path.endswith('/workflows/ci.yml'):
            return self.workflow
        if '/runs?' in path:
            return {'total_count': 2 if self.partial_runs else 1,
                    'workflow_runs': [copy.deepcopy(self.run)]}
        if '/jobs?' in path:
            return {'total_count': len(self.jobs) + int(self.partial_jobs), 'jobs': self.jobs}
        return self.final if self.final and len(self.calls) == 5 else copy.deepcopy(self.run)

    def select(self):
        return MODULE.select_proof(SHA, self.fetch, NOW)

    def test_exact_source_all_authoritative_lanes_in_same_attempt(self):
        self.assertEqual(self.select(), {'source_sha': SHA, 'run_id': 101,
                                        'attempt': 2, 'workflow_id': 51})
        self.assertEqual(len(self.calls), 5)
        self.assertIn('/attempts/2/jobs?', self.calls[3])

    def test_rejects_untrusted_or_incomplete_runs(self):
        changes = {'event': 'pull_request', 'head_branch': 'feature', 'head_sha': 'b' * 40,
                   'workflow_id': 99, 'path': '.github/workflows/other.yml',
                   'status': 'in_progress', 'conclusion': 'failure', 'run_attempt': 0,
                   'repository': {'full_name': 'example-org/example-app'},
                   'head_repository': {'full_name': 'example-org/example-app'},
                   'updated_at': '2025-12-31T23:59:59Z'}
        original = copy.deepcopy(self.run)
        for key, value in changes.items():
            with self.subTest(key=key):
                self.run = {**original, key: value}
                self.assertIsNone(self.select())
        self.run = original
        for event in ['workflow_dispatch', 'schedule', 'workflow_run']:
            self.run['event'] = event
            self.assertIsNone(self.select())

    def test_old_tests_cannot_be_refreshed_by_later_deployment_completion(self):
        self.run['run_started_at'] = '2025-12-31T23:59:59Z'
        self.assertIsNone(self.select())

    def test_rejects_future_approval(self):
        self.run['updated_at'] = '2026-01-02T00:00:01Z'
        self.assertIsNone(self.select())

    def test_rejects_every_missing_duplicate_failed_skipped_or_inherited_lane(self):
        original = copy.deepcopy(self.jobs)
        for name in MODULE.REQUIRED_JOBS:
            for change in ['missing', 'duplicate', 'failure', 'skipped', 'cancelled',
                           'queued', 'wrong_source', 'wrong_run', 'inherited']:
                with self.subTest(name=name, change=change):
                    self.jobs = copy.deepcopy(original)
                    job = next(job for job in self.jobs if job['name'] == name)
                    if change == 'missing':
                        self.jobs.remove(job)
                    elif change == 'duplicate':
                        self.jobs.append(copy.deepcopy(job))
                    elif change == 'queued':
                        job['status'] = 'queued'
                    elif change == 'wrong_source':
                        job['head_sha'] = 'b' * 40
                    elif change == 'wrong_run':
                        job['run_id'] = 999
                    elif change == 'inherited':
                        job['run_attempt'] = 1
                    else:
                        job['conclusion'] = change
                    self.assertIsNone(self.select())

    def test_rejects_partial_pagination(self):
        self.partial_runs = True
        self.assertIsNone(self.select())
        self.partial_runs = False
        self.partial_jobs = True
        self.assertIsNone(self.select())

    def test_rejects_wrong_canonical_workflow(self):
        self.workflow['path'] = '.github/workflows/other.yml'
        self.assertIsNone(self.select())

    def test_rerun_after_job_read_invalidates_approval(self):
        self.final = {**self.run, 'run_attempt': 3, 'status': 'in_progress'}
        self.assertIsNone(self.select())

    def test_rerun_before_job_read_requires_current_attempt(self):
        original = self.fetch
        def rerun(path):
            response = original(path)
            if '/runs/101' in path and '/jobs?' not in path:
                response['run_attempt'] = 3
            return response
        self.assertIsNone(MODULE.select_proof(SHA, rerun, NOW))

    def test_api_failure_at_every_boundary_falls_back(self):
        for fail_at in range(1, 6):
            for error in [subprocess.TimeoutExpired('gh', 10), ValueError('invalid JSON'),
                          OSError('unavailable'), KeyError('missing field')]:
                with self.subTest(fail_at=fail_at, error=type(error).__name__):
                    self.calls = []
                    def failing(path):
                        if len(self.calls) + 1 == fail_at:
                            raise error
                        return self.fetch(path)
                    self.assertIsNone(MODULE.select_proof(SHA, failing, NOW))

    def test_invalid_sha_never_queries_api(self):
        self.assertIsNone(MODULE.select_proof('not-a-sha', self.fetch, NOW))
        self.assertEqual(self.calls, [])

    def test_cli_reports_proof_or_full_fallback_without_secret_output(self):
        for proof in [None, {'source_sha': SHA, 'run_id': 101, 'attempt': 2, 'workflow_id': 51}]:
            with tempfile.TemporaryDirectory() as temporary:
                output, summary = Path(temporary) / 'output', Path(temporary) / 'summary'
                with patch.dict(os.environ, {'COMMIT': SHA, 'GITHUB_OUTPUT': str(output),
                                             'GITHUB_STEP_SUMMARY': str(summary)}):
                    with patch.object(MODULE, 'select_proof', return_value=proof):
                        MODULE.main()
                self.assertIn(f'reuse={str(proof is not None).lower()}', output.read_text())
                self.assertIn('Release verification', summary.read_text())
                if proof:
                    for value in [SHA, '101', '2', '51']:
                        self.assertIn(value, output.read_text())

    def test_manual_release_of_old_tag_without_verifier_selects_full_checks(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        approval = workflow.split('      - name: Check recent exact-source main CI')[1]
        body = approval.split('        run: |\n')[1].split('\n      - name: Setup PHP')[0]
        script = '\n'.join(line[10:] for line in body.splitlines())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            subprocess.run(['bash', '-euo', 'pipefail', '-c', script], check=True,
                           cwd=temporary, env={**os.environ, 'GITHUB_OUTPUT': str(output)})
            self.assertIn('reuse=false', output.read_text())
            self.assertIn('evidence=Full verification on the tagged commit', output.read_text())

    def test_release_retains_fresh_audit_and_full_fallback_before_build(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        verify = workflow.split('\n  verify:')[1].split('\n  build:')[0]
        self.assertIn('actions: read', verify)
        self.assertIn('if [ -f scripts/release/verified-main.py ]; then', verify)
        self.assertIn("echo 'reuse=false'", verify)
        self.assertIn('python3 scripts/release/verified-main.py', verify)
        for name in ['Setup Node', 'Enable pnpm', 'Setup application', 'Run CI checks',
                     'Test deployment hooks']:
            self.assertIn(f"- name: {name}\n        if: steps.approval.outputs.reuse != 'true'", verify)
        self.assertIn("- name: Audit locked dependencies again\n        if: steps.approval.outputs.reuse == 'true'\n        run: composer audit --locked", verify)
        self.assertIn('needs: [resolve, verify]', workflow)
        self.assertIn('needs: [resolve, verify, build]', workflow)
        self.assertIn('echo "Verification: $VERIFICATION"', workflow)
