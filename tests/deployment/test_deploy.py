import base64
import fcntl
import json
import importlib.util
import io
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('identity_deploy', Path(__file__).resolve().parents[2] / 'scripts/deployment/deploy.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IdentityDeployTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve() / 'auth-manager-staging'
        self.root.mkdir()
        for ancestor in (self.root, Path(self.directory.name)):
            ancestor.chmod(0o755)
        self.url = 'https://identity.example.test'
        (self.root / '.identity-instance').write_text('staging ' + self.url)
        (self.root / 'shared/storage/app/private/oauth').mkdir(parents=True)
        (self.root / 'shared/.env').write_text('SYNTHETIC_CONFIGURATION=true')
        for key in ('oauth-private.key', 'oauth-public.key'):
            (self.root / 'shared/storage/app/private/oauth' / key).write_text('synthetic-key')
        self.old_sha = 'a' * 40
        self.sha = 'b' * 40
        self.engine_sha = 'c' * 40
        self.release_id = self.sha + '-123-1'
        self.previous = self.root / 'releases' / (self.old_sha + '-122-1')
        (self.previous / 'public').mkdir(parents=True)
        (self.previous / 'public/deployment-revision.txt').write_text(self.old_sha)
        (self.root / 'releases').chmod(0o755)
        (self.previous / 'public/deployment-release.txt').write_text(self.previous.name)
        (self.root / 'current').symlink_to(self.previous)
        (self.root / 'incoming').mkdir()
        self.policy = {
            'contract_version': 1, 'environment': 'staging', 'url': self.url,
            'database': 'auth_manager_staging', 'database_user': 'auth_manager_staging',
            'application_name': 'Example Identity', 'branding': {
                'enabled': True, 'logo_light': '/branding/logo-light.svg',
                'logo_dark': '/branding/logo-dark.svg', 'favicon': '/branding/favicon.ico',
                'stylesheet': '/branding/theme.css',
            },
        }
        self.policy_path = self.root / '.deployment-policy.json'
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o600)
        self.engine_path = self.root / 'incoming' / (self.release_id + '.engine-' + self.engine_sha + '.py')
        self.engine_path.write_text('# synthetic engine fixture')
        self.engine_path.chmod(0o400)
        engine = patch.object(MODULE, '__file__', str(self.engine_path))
        engine.start()
        self.addCleanup(engine.stop)
        self.archive = self.root / 'incoming' / (self.release_id + '.tar.gz')
        with tarfile.open(self.archive, 'w:gz') as bundle:
            entry = tarfile.TarInfo('public/deployment-revision.txt')
            payload = self.sha.encode()
            entry.size = len(payload)
            bundle.addfile(entry, io.BytesIO(payload))
            entry = tarfile.TarInfo('public/deployment-release.txt')
            entry.size = len(self.release_id)
            bundle.addfile(entry, io.BytesIO(self.release_id.encode()))
            for name in ('logo-light.svg', 'logo-dark.svg', 'favicon.ico', 'theme.css'):
                entry = tarfile.TarInfo('public/branding/' + name)
                entry.size = 9
                bundle.addfile(entry, io.BytesIO(b'synthetic'))

    def deploy(self):
        MODULE.deploy(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)

    def test_migrations_and_caches_finish_before_public_switch(self):
        commands = []

        def runner(*args, cwd=None):
            commands.append(args)
            if args[0] == 'php':
                self.assertEqual((self.root / 'current').resolve(), self.previous)

        with patch.object(MODULE, 'run', runner), patch.object(MODULE, 'health') as health:
            self.deploy()
        self.assertLess(commands.index(('php', 'artisan', 'migrate', '--force', '--no-interaction')),
                        commands.index(('php', 'artisan', 'config:cache')))
        self.assertEqual((self.root / 'current').resolve().name, self.release_id)
        health.assert_called_once_with(self.url, self.sha, self.release_id)
        self.assertEqual((self.root / 'current/.env').resolve(), self.root / 'shared/.env')
        self.assertEqual((self.root / 'current/storage').resolve(), self.root / 'shared/storage')

    def test_private_worker_umask_keeps_public_assets_readable_without_exposing_secrets(self):
        secret = self.root / 'shared/.env'
        secret.chmod(0o600)
        key = self.root / 'shared/storage/app/private/oauth/oauth-private.key'
        key.chmod(0o600)
        previous_mask = MODULE.os.umask(0o077)
        try:
            with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'):
                self.deploy()
        finally:
            MODULE.os.umask(previous_mask)
        candidate = (self.root / 'current').resolve()
        for directory in (candidate, candidate / 'public', candidate / 'public/branding'):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        for asset in (candidate / 'public').rglob('*'):
            if asset.is_file():
                self.assertEqual(asset.stat().st_mode & 0o777, 0o644)
        self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_activation_starts_and_checks_provisioned_queue_unit(self):
        with patch.object(MODULE, 'run') as run, patch.object(MODULE, 'health'):
            self.deploy()
        commands = [call.args for call in run.call_args_list]
        self.assertEqual(commands[-2:], [
            ('sudo', '-n', '/usr/bin/systemctl', 'restart', 'auth-manager-queue.service'),
            ('sudo', '-n', '/usr/bin/systemctl', 'is-active', '--quiet', 'auth-manager-queue.service'),
        ])

    def test_inactive_queue_rolls_back_and_restarts_previous_release(self):
        checked = []
        def runner(*args, cwd=None):
            if 'is-active' in args:
                checked.append((self.root / 'current').resolve())
                if len(checked) == 1:
                    raise subprocess.CalledProcessError(3, 'synthetic inactive queue')
        with patch.object(MODULE, 'run', runner), patch.object(MODULE, 'health'):
            with self.assertRaises(subprocess.CalledProcessError):
                self.deploy()
        self.assertEqual(checked, [self.root / 'releases' / self.release_id, self.previous])
        self.assertEqual((self.root / 'current').resolve(), self.previous)

    def test_private_release_ancestors_fail_before_activation(self):
        for ancestor in (self.root, self.root / 'releases'):
            with self.subTest(ancestor=ancestor.name):
                ancestor.chmod(0o700)
                try:
                    with patch.object(MODULE, 'run') as run:
                        with self.assertRaisesRegex(RuntimeError, 'traversal'):
                            self.deploy()
                    run.assert_not_called()
                finally:
                    ancestor.chmod(0o755)

    def test_nested_storage_alias_cannot_cross_application_boundary(self):
        outside = self.root / 'other-storage'
        outside.mkdir()
        (self.root / 'shared/storage/framework').symlink_to(outside)
        with patch.object(MODULE, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'aliases'):
                self.deploy()
        run.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_definitive_spawn_failure_is_terminal(self):
        with patch.object(MODULE.subprocess, 'run', side_effect=FileNotFoundError('synthetic missing launcher')):
            with self.assertRaises(FileNotFoundError):
                MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_same_revision_old_release_is_not_healthy(self):
        with patch.object(MODULE, 'run'), patch.object(MODULE.subprocess, 'check_output', side_effect=[self.sha, self.sha + '-122-1']):
            with self.assertRaisesRegex(RuntimeError, 'release ID'):
                MODULE.health(self.url, self.sha, self.release_id)

    def test_second_termination_cannot_skip_pointer_rollback(self):
        ignored = False
        stops = 0
        original = MODULE.point_current
        def handler(signum, action):
            nonlocal ignored, stops
            if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                stops += 1
                if stops == 1:
                    raise InterruptedError('synthetic repeated stop before ignore')
                ignored = True
        def point(root, target):
            if target == self.previous and not ignored:
                raise InterruptedError('synthetic repeated stop during rollback')
            original(root, target)
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=[RuntimeError('unhealthy'), None]), patch.object(MODULE.signal, 'signal', handler), patch.object(MODULE, 'point_current', point):
            with self.assertRaisesRegex(RuntimeError, 'unhealthy'):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertTrue(ignored)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_migration_failure_keeps_previous_release_serving(self):
        def runner(*args, cwd=None):
            if 'migrate' in args:
                raise subprocess.CalledProcessError(1, 'synthetic migration failure')
        with patch.object(MODULE, 'run', runner), patch.object(MODULE, 'health') as health:
            with self.assertRaises(subprocess.CalledProcessError):
                self.deploy()
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        health.assert_not_called()

    def test_failed_candidate_health_rolls_back_and_verifies_previous(self):
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=[RuntimeError('unhealthy'), None]) as health:
            with self.assertRaisesRegex(RuntimeError, 'unhealthy'):
                self.deploy()
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(health.call_args_list[1].args, (self.url, self.old_sha, self.previous.name))

    def test_failed_first_release_removes_public_pointer(self):
        (self.root / 'current').unlink()
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=RuntimeError('unhealthy')):
            with self.assertRaises(RuntimeError):
                self.deploy()
        self.assertFalse((self.root / 'current').is_symlink())

    def test_wrong_instance_marker_cannot_run_migrations(self):
        (self.root / '.identity-instance').write_text('prod https://other.example.test')
        with patch.object(MODULE, 'run') as run:
            with self.assertRaises(RuntimeError):
                self.deploy()
        run.assert_not_called()

    def test_missing_keys_cannot_run_migrations(self):
        (self.root / 'shared/storage/app/private/oauth/oauth-private.key').unlink()
        with patch.object(MODULE, 'run') as run:
            with self.assertRaises(RuntimeError):
                self.deploy()
        run.assert_not_called()

    def test_rejects_archive_traversal_before_running_code(self):
        with tarfile.open(self.archive, 'w:gz') as bundle:
            entry = tarfile.TarInfo('../escaped')
            entry.size = 0
            bundle.addfile(entry, io.BytesIO())
        with patch.object(MODULE, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Unsafe archive'):
                self.deploy()
        run.assert_not_called()
        self.assertFalse((self.root / 'releases/escaped').exists())

    def test_failed_configuration_validation_does_not_switch(self):
        with patch.object(MODULE, 'run', side_effect=subprocess.CalledProcessError(1, 'synthetic invalid configuration')):
            with self.assertRaises(subprocess.CalledProcessError):
                self.deploy()
        self.assertEqual((self.root / 'current').resolve(), self.previous)

    def test_keys_cannot_alias_another_instance(self):
        key = self.root / 'shared/storage/app/private/oauth/oauth-private.key'
        key.unlink()
        outside = self.root.parent / 'another-instance-key'
        outside.write_text('synthetic-key')
        key.symlink_to(outside)
        with patch.object(MODULE, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'isolated signing keys'):
                self.deploy()
        run.assert_not_called()

    def test_php_preflight_rejects_url_and_shared_cache_overrides(self):
        for override in ({'database.connections.mysql': {'database': 'auth_manager_staging', 'username': 'auth_manager_staging', 'url': 'mysql://other.example.test/shared'}}, {'cache.default': 'redis'}, {'session.connection': 'shared'}):
            with self.subTest(override=override):
                self.assert_php_preflight(override, expected_success=False)

    def test_php_preflight_rejects_unbranded_or_cross_origin_branding(self):
        for overrides in ({'branding.enabled': False}, {'app.name': 'Other'}, {'branding.logo_light': 'https://example.test/logo.svg'}):
            self.assert_php_preflight(overrides, expected_success=False)

    def test_php_preflight_accepts_isolated_database_configuration(self):
        self.assert_php_preflight({}, expected_success=True)

    def assert_php_preflight(self, overrides, expected_success):
        configuration = {
            'app.name': 'Example Identity', 'branding.enabled': True,
            'branding.logo_light': '/branding/logo-light.svg', 'branding.logo_dark': '/branding/logo-dark.svg',
            'branding.favicon': '/branding/favicon.ico', 'branding.stylesheet': '/branding/theme.css',
            'database.default': 'mysql',
            'database.connections.mysql': {'database': 'auth_manager_staging', 'username': 'auth_manager_staging', 'url': None},
            'app.url': self.url, 'app.env': 'staging', 'app.key': 'synthetic-key',
            'session.driver': 'database', 'session.connection': None,
            'session.domain': None, 'session.cookie': 'auth_manager_staging_session',
            'cache.default': 'database', 'cache.stores.database.connection': None,
            'queue.default': 'database', 'queue.connections.database.connection': None,
        }
        configuration.update(overrides)
        encoded = base64.b64encode(json.dumps(configuration).encode()).decode()
        captured = []
        # Capture the actual inline PHP contract without activating or migrating.
        def capture(*args, cwd=None):
            if args[1] == '-r':
                captured.extend(args)
                raise RuntimeError('captured')
        release = self.root / 'releases' / self.release_id
        if release.exists():
            import shutil
            shutil.rmtree(release)
        with patch.object(MODULE, 'run', capture):
            with self.assertRaisesRegex(RuntimeError, 'captured'):
                self.deploy()
        (release / 'vendor').mkdir()
        (release / 'bootstrap').mkdir()
        (release / 'vendor/autoload.php').write_text("<?php function config($key, $default = null) { $data = json_decode(base64_decode('" + encoded + "'), true); return array_key_exists($key, $data) ? $data[$key] : $default; }")
        (release / 'bootstrap/app.php').write_text("<?php return new class { function make($contract) { return new class { function bootstrap() {} }; } };")
        result = subprocess.run(captured, cwd=release, capture_output=True)
        self.assertEqual(result.returncode == 0, expected_success, result.stderr.decode())

    def test_concurrent_deploy_cannot_enter_activation(self):
        with (self.root / '.deploy.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(MODULE, 'run') as run:
                with self.assertRaises(BlockingIOError):
                    self.deploy()
            run.assert_not_called()

    def test_archive_symlink_cannot_escape_candidate(self):
        with tarfile.open(self.archive, 'w:gz') as bundle:
            entry = tarfile.TarInfo('escape')
            entry.type = tarfile.SYMTYPE
            entry.linkname = '/etc'
            bundle.addfile(entry)
        with patch.object(MODULE, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Unsafe archive'):
                self.deploy()
        run.assert_not_called()

    def test_activation_launch_uses_persistent_systemd_unit_and_reserves_release(self):
        with patch.object(MODULE.subprocess, 'run') as launch:
            MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        command = launch.call_args.args[0]
        self.assertEqual(command[:4], ['systemd-run', '--user', '--quiet', '--collect'])
        self.assertIn('--property=RuntimeMaxSec=900', command)
        self.assertIn('--property=TimeoutStopSec=120', command)
        self.assertIn('worker', command)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'queued')
        with patch.object(MODULE.subprocess, 'run') as duplicate:
            with self.assertRaises(FileExistsError):
                MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        duplicate.assert_not_called()

    def test_worker_persists_health_verified_success_after_launcher_is_gone(self):
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'), patch.object(MODULE.signal, 'signal'):
            MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        status = json.loads(MODULE.status_path(self.root, self.release_id).read_text())
        self.assertEqual(status, {'contract_version': 1, 'state': 'succeeded', 'revision': self.sha, 'engine_revision': self.engine_sha, 'release_id': self.release_id})
        self.assertEqual((self.root / 'current').resolve().name, self.release_id)

    def test_interrupted_worker_rolls_back_and_persists_failure(self):
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=[InterruptedError('synthetic service stop'), None]), patch.object(MODULE.signal, 'signal'):
            with self.assertRaises(InterruptedError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_ambiguous_systemd_launch_failure_preserves_reserved_status(self):
        with patch.object(MODULE.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'systemd-run')):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'queued')

    def test_success_status_write_failure_rolls_back_before_failure_is_recorded(self):
        original = MODULE.write_status
        def status(root, release_id, sha, state, engine_sha):
            if state == 'succeeded':
                raise OSError('synthetic status filesystem failure')
            original(root, release_id, sha, state, engine_sha)
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'), patch.object(MODULE.signal, 'signal'), patch.object(MODULE, 'write_status', status):
            with self.assertRaises(OSError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_termination_is_deferred_until_success_status_is_durable(self):
        events = []
        original = MODULE.write_status
        def status(root, release_id, sha, state, engine_sha):
            original(root, release_id, sha, state, engine_sha)
            events.append(('status', state))
        def handler(signum, action):
            if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                events.append(('ignore', signum))
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'), patch.object(MODULE.signal, 'signal', handler), patch.object(MODULE, 'write_status', status):
            MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertLess(events.index(('ignore', MODULE.signal.SIGTERM)), events.index(('status', 'succeeded')))
        self.assertEqual(events[-1], ('status', 'succeeded'))

    def test_interruption_after_running_transition_persists_failure_without_activation(self):
        original = MODULE.write_status
        def status(root, release_id, sha, state, engine_sha):
            original(root, release_id, sha, state, engine_sha)
            if state == 'running':
                raise InterruptedError('synthetic stop immediately after startup transition')
        with patch.object(MODULE, 'run') as run, patch.object(MODULE.signal, 'signal'), patch.object(MODULE, 'write_status', status):
            with self.assertRaises(InterruptedError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        run.assert_not_called()
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_worker_validation_failure_replaces_existing_queue_reservation(self):
        for failure in (RuntimeError, InterruptedError):
            with self.subTest(failure=failure.__name__):
                MODULE.write_status(self.root, self.release_id, self.sha, 'queued', self.engine_sha)
                with patch.object(MODULE, 'validate_target', side_effect=failure('synthetic validation failure')), patch.object(MODULE.signal, 'signal'), patch.object(MODULE, 'deploy') as deploy:
                    with self.assertRaises(failure):
                        MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
                deploy.assert_not_called()
                self.assertEqual((self.root / 'current').resolve(), self.previous)
                self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_launcher_timeout_cannot_overwrite_a_worker_committed_result(self):
        def manager(*args, **kwargs):
            MODULE.write_status(self.root, self.release_id, self.sha, 'succeeded', self.engine_sha)
            raise subprocess.TimeoutExpired('systemd-run', 30)
        with patch.object(MODULE.subprocess, 'run', manager):
            with self.assertRaises(subprocess.TimeoutExpired):
                MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'succeeded')

    def test_signal_finalization_failure_cannot_preserve_success_after_rollback(self):
        for failure in (OSError, ValueError):
            with self.subTest(failure=failure):
                if (self.root / 'releases' / self.release_id).exists():
                    shutil.rmtree(self.root / 'releases' / self.release_id)
                def handler(signum, action):
                    if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                        raise failure('synthetic signal finalization failure')
                with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'), patch.object(MODULE.signal, 'signal', handler):
                    with self.assertRaises(failure):
                        MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
                self.assertEqual((self.root / 'current').resolve(), self.previous)
                self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_success_is_never_visible_before_signal_setup_can_fail(self):
        states = []
        original = MODULE.write_status
        def status(*args):
            original(*args)
            states.append(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'])
        def handler(signum, action):
            if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                raise OSError('synthetic signal setup failure')
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'), patch.object(MODULE.signal, 'signal', handler), patch.object(MODULE, 'write_status', status):
            with self.assertRaises(OSError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual(states, ['running', 'failed'])

    def test_repeated_termination_during_failure_publication_still_records_failure(self):
        # First stop interrupts activation; a second stop lands while the failure handler runs.
        events = []
        original = MODULE.write_status
        def status(root, release_id, sha, state, engine_sha):
            if state == 'failed' and ('interrupted', 'failed') not in events:
                events.append(('interrupted', 'failed'))
                raise InterruptedError('synthetic second service stop during failure publication')
            original(root, release_id, sha, state, engine_sha)
            events.append(('status', state))
        def handler(signum, action):
            if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                events.append(('ignore', signum))
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=[InterruptedError('synthetic service stop'), None]), patch.object(MODULE.signal, 'signal', handler), patch.object(MODULE, 'write_status', status):
            with self.assertRaises(InterruptedError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')
        self.assertLess(events.index(('ignore', MODULE.signal.SIGTERM)), events.index(('interrupted', 'failed')))
        self.assertEqual(events[-1], ('status', 'failed'))

    def test_failure_is_recorded_even_when_signal_disposition_cannot_change(self):
        def handler(signum, action):
            if signum == MODULE.signal.SIGTERM and action == MODULE.signal.SIG_IGN:
                raise OSError('synthetic signal disposition failure')
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health', side_effect=[RuntimeError('synthetic unhealthy candidate'), None]), patch.object(MODULE.signal, 'signal', handler):
            with self.assertRaises(RuntimeError):
                MODULE.worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertEqual((self.root / 'current').resolve(), self.previous)
        self.assertEqual(json.loads(MODULE.status_path(self.root, self.release_id).read_text())['state'], 'failed')

    def test_public_revision_mismatch_is_unhealthy(self):
        with patch.object(MODULE, 'run'), patch.object(MODULE.subprocess, 'check_output', return_value='wrong-sha'):
            with self.assertRaisesRegex(RuntimeError, 'revision'):
                MODULE.health(self.url, self.sha, self.release_id)


    def test_policy_mismatch_prevents_commands_and_public_switch(self):
        for field, value in (('environment', 'prod'), ('url', 'https://other.example.test'),
                             ('database', 'auth_manager_other'), ('contract_version', 2)):
            with self.subTest(field=field):
                self.policy_path.write_text(json.dumps({**self.policy, field: value}))
                with patch.object(MODULE, 'run') as run:
                    with self.assertRaises(RuntimeError):
                        self.deploy()
                run.assert_not_called()
                self.assertEqual(self.previous, (self.root / 'current').resolve())

    def test_missing_aliased_oversized_and_writable_policy_are_rejected(self):
        self.policy_path.unlink()
        with self.assertRaises(RuntimeError):
            self.deploy()
        outside = self.root.parent / 'policy.json'
        outside.write_text(json.dumps(self.policy))
        self.policy_path.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            self.deploy()
        self.policy_path.unlink()
        self.policy_path.write_text(' ' * 16385)
        with self.assertRaises(RuntimeError):
            self.deploy()
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o666)
        with self.assertRaises(RuntimeError):
            self.deploy()

    def test_unknown_duplicate_and_unsafe_policy_fields_fail_closed(self):
        values = [{**self.policy, 'unexpected': True},
                  {**self.policy, 'contract_version': True},
                  {**self.policy, 'database_user': 'shared_application'},
                  {**self.policy, 'branding': {'enabled': 'false'}},
                  {**self.policy, 'branding': {**self.policy['branding'], 'stylesheet': 'https://assets.example.test/theme.css'}},
                  {**self.policy, 'branding': {**self.policy['branding'], 'logo_light': '/branding/../other.svg'}}]
        for value in values:
            with self.subTest(value=value):
                self.policy_path.write_text(json.dumps(value))
                with self.assertRaises(RuntimeError):
                    self.deploy()
        self.policy_path.write_text(json.dumps(self.policy).replace('"contract_version": 1', '"contract_version": 1, "contract_version": 1'))
        with self.assertRaises(ValueError):
            self.deploy()

    def test_policy_checks_exact_database_principal_and_application_name(self):
        for override in ({'app.name': 'Different Identity'},
                         {'database.connections.mysql': {'database': 'auth_manager_staging', 'username': 'auth_manager_other', 'url': None}}):
            self.assert_php_preflight(override, expected_success=False)

    def test_stock_branding_keeps_bundled_styles_without_requiring_custom_assets(self):
        self.policy['branding'] = {'enabled': False}
        self.policy_path.write_text(json.dumps(self.policy))
        with tarfile.open(self.archive, 'w:gz') as bundle:
            for name, payload in (('public/deployment-revision.txt', self.sha.encode()),
                                  ('public/deployment-release.txt', self.release_id.encode()),
                                  ('public/build/default.css', b':root {color:black} .dark {color:white}')):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
        self.assert_php_preflight({'branding.enabled': False}, expected_success=True)
        shutil.rmtree(self.root / 'releases' / self.release_id)
        with patch.object(MODULE, 'run'), patch.object(MODULE, 'health'):
            self.deploy()
        self.assertFalse((self.root / 'current/public/branding').exists())
        self.assertEqual(b':root {color:black} .dark {color:white}', (self.root / 'current/public/build/default.css').read_bytes())

    def test_engine_and_application_pins_travel_independently_to_worker_and_status(self):
        with patch.object(MODULE.subprocess, 'run') as run:
            MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        command = run.call_args.args[0]
        self.assertIn(str(self.engine_path), command)
        self.assertEqual(self.sha, command[command.index('--app-sha') + 1])
        self.assertEqual(self.engine_sha, command[command.index('--engine-sha') + 1])
        status = json.loads(MODULE.status_path(self.root, self.release_id).read_text())
        self.assertEqual(self.sha, status['revision'])
        self.assertEqual(self.engine_sha, status['engine_revision'])
        self.assertEqual(1, status['contract_version'])

    def test_wrong_mutable_or_aliased_engine_never_starts_or_reserves_status(self):
        for engine_sha in ('bad-revision', 'd' * 40):
            with patch.object(MODULE.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', engine_sha)
            run.assert_not_called()
        self.engine_path.chmod(0o600)
        with self.assertRaises(RuntimeError):
            MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.engine_path.unlink()
        self.engine_path.symlink_to(self.policy_path)
        with self.assertRaises(RuntimeError):
            MODULE.launch_worker(self.root, 'staging', self.release_id, self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertFalse(MODULE.status_path(self.root, self.release_id).exists())

    def test_invalid_worker_identity_cannot_publish_status_outside_incoming(self):
        with self.assertRaises(RuntimeError):
            MODULE.worker(self.root, 'staging', '../escaped', self.sha, self.url, 'auth_manager_staging', self.engine_sha)
        self.assertFalse((self.root / 'escaped.status.json').exists())
        self.assertFalse(MODULE.status_path(self.root, self.release_id).exists())


if __name__ == '__main__':
    unittest.main()
