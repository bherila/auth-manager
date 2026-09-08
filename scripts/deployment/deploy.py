#!/usr/bin/env python3
"""Activate a prebuilt identity release; runtime state is provisioned separately."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import signal
import tarfile
from urllib.parse import urlsplit



def validate_location(root, release_id, sha, engine_sha):
    root = Path(root)
    if (not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{40}', sha)
            or not isinstance(engine_sha, str) or not re.fullmatch(r'[a-f0-9]{40}', engine_sha)
            or not isinstance(release_id, str) or not re.fullmatch(re.escape(sha) + r'-[0-9]+-[0-9]+', release_id)
            or not root.is_absolute() or root.resolve() != root
            or not re.fullmatch(r'auth-manager-(staging|prod)', root.name)):
        raise RuntimeError('Invalid release or engine identity')
    incoming = root / 'incoming'
    if not incoming.is_dir() or incoming.resolve() != incoming:
        raise RuntimeError('Incoming directory must be provisioned without aliases')
    return root


def validate_engine(root, release_id, engine_sha):
    expected = root / 'incoming' / (release_id + '.engine-' + engine_sha + '.py')
    actual = Path(__file__).absolute()
    if (actual != expected or actual.resolve() != actual or not actual.is_file()
            or actual.stat().st_mode & 0o222):
        raise RuntimeError('Activation requires its read-only per-release engine copy')
    return actual


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate deployment policy field')
        result[key] = value
    return result


def load_policy(root):
    path = root / '.deployment-policy.json'
    if not path.is_file() or path.resolve() != path or path.stat().st_mode & 0o022:
        raise RuntimeError('A protected server-owned deployment policy is required')
    with path.open('rb') as handle:
        content = handle.read(16385)
    if len(content) > 16384:
        raise RuntimeError('Deployment policy exceeds the supported size')
    policy = json.loads(content.decode('utf-8'), object_pairs_hook=unique_object)
    fields = {'contract_version', 'environment', 'url', 'database', 'database_user', 'application_name', 'branding'}
    if (not isinstance(policy, dict) or set(policy) != fields
            or type(policy['contract_version']) is not int or policy['contract_version'] != 1
            or policy['environment'] not in ('staging', 'prod')
            or not isinstance(policy['url'], str) or not re.fullmatch(r'https://[A-Za-z0-9.-]+', policy['url'])
            or any(not isinstance(policy[key], str) or not re.fullmatch(r'auth_manager_[A-Za-z0-9_]+', policy[key]) for key in ('database', 'database_user'))
            or not isinstance(policy['application_name'], str) or not policy['application_name'].strip()
            or len(policy['application_name']) > 100 or re.search(r'[\x00-\x1f\x7f]', policy['application_name'])):
        raise RuntimeError('Invalid deployment policy')
    branding = policy['branding']
    if not isinstance(branding, dict) or type(branding.get('enabled')) is not bool:
        raise RuntimeError('Deployment policy must explicitly select default or custom branding')
    extensions = {'logo_light': ('svg', 'png', 'webp', 'jpg', 'jpeg'),
                  'logo_dark': ('svg', 'png', 'webp', 'jpg', 'jpeg'),
                  'favicon': ('ico', 'svg', 'png'), 'stylesheet': ('css',)}
    if not branding['enabled']:
        if set(branding) != {'enabled'}:
            raise RuntimeError('Default branding must not specify custom assets')
    else:
        if set(branding) != {'enabled', *extensions}:
            raise RuntimeError('Custom branding requires the complete asset set')
        for key, allowed in extensions.items():
            asset = branding[key]
            if (not isinstance(asset, str) or not re.fullmatch(r'/branding/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.[a-z]+', asset)
                    or asset.rsplit('.', 1)[-1] not in allowed):
                raise RuntimeError('Branding policy requires local asset paths')
    return policy


def status_record(release_id, sha, state, engine_sha):
    return {'contract_version': 1, 'state': state, 'revision': sha,
            'engine_revision': engine_sha, 'release_id': release_id}

def run(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL, timeout=300)


def health(url, sha, release_id):
    run('curl', '--fail', '--silent', '--show-error', '--max-time', '15',
        '--retry', '4', '--retry-delay', '2', '--retry-all-errors',
        '--header', 'Cache-Control: no-cache', url + '/up')
    revision = subprocess.check_output([
        'curl', '--fail', '--silent', '--show-error', '--max-time', '15',
        '--header', 'Cache-Control: no-cache', url + '/deployment-revision.txt?revision=' + sha,
    ], text=True, timeout=30).strip()
    if revision != sha:
        raise RuntimeError('Public revision does not match the candidate release')
    deployed = subprocess.check_output([
        'curl', '--fail', '--silent', '--show-error', '--max-time', '15',
        '--header', 'Cache-Control: no-cache', url + '/deployment-release.txt?release=' + release_id,
    ], text=True, timeout=30).strip()
    if deployed != release_id:
        raise RuntimeError('Public release ID does not match the candidate release')


def point_current(root, target):
    temporary = root / '.current-next'
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(target)
    os.replace(temporary, root / 'current')


def validate_target(root, environment, release_id, sha, url, database, engine_sha):
    root = validate_location(root, release_id, sha, engine_sha)
    parsed = urlsplit(url)
    if (environment not in ('staging', 'prod')
            or not re.fullmatch(r'[a-f0-9]{40}', sha)
            or not re.fullmatch(re.escape(sha) + r'-[0-9]+-[0-9]+', release_id)
            or not re.fullmatch(r'auth_manager_[A-Za-z0-9_]+', database)
            or not root.is_absolute() or root.is_symlink()
            or root.name != 'auth-manager-' + environment
            or parsed.scheme != 'https' or not parsed.hostname
            or parsed.username or parsed.password or parsed.port
            or parsed.path or parsed.query or parsed.fragment
):
        raise RuntimeError('Invalid deployment configuration')
    if root.resolve() != root:
        raise RuntimeError('Deployment root must be canonical and must not traverse symlinks')
    if (root / '.identity-instance').read_text().strip() != environment + ' ' + url:
        raise RuntimeError('Provisioned instance marker does not match the target')
    incoming = root / 'incoming'
    if not incoming.is_dir() or incoming.resolve() != incoming:
        raise RuntimeError('Incoming directory must be provisioned without aliases')
    policy = load_policy(root)
    if any(policy[key] != value for key, value in (('environment', environment), ('url', url), ('database', database))):
        raise RuntimeError('Deployment policy does not match the requested target')
    return root


def deploy(root, environment, release_id, sha, url, database, engine_sha, on_success=None):
    root = validate_target(root, environment, release_id, sha, url, database, engine_sha)
    with (root / '.deploy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        activate(root, environment, release_id, sha, url, database, engine_sha, on_success)


def activate(root, environment, release_id, sha, url, database, engine_sha, on_success=None):
    policy = load_policy(root)
    shared = root / 'shared'
    if not (shared / '.env').is_file() or (shared / '.env').is_symlink():
        raise RuntimeError('A server-owned environment file is required')
    storage = shared / 'storage'
    for key in ('oauth-private.key', 'oauth-public.key'):
        key_path = storage / 'app/private/oauth' / key
        if not key_path.is_file() or key_path.stat().st_size == 0 or key_path.resolve() != key_path:
            raise RuntimeError('Provisioned isolated signing keys are required')
    current = root / 'current'
    if current.exists() and not current.is_symlink():
        raise RuntimeError('Current must be an atomic release symlink')
    previous = current.resolve() if current.is_symlink() else None
    releases = root / 'releases'
    if releases.is_symlink() or shared.is_symlink() or storage.is_symlink():
        raise RuntimeError('Persistent directories must not alias another application')
    if previous is not None and (not previous.is_dir() or previous.parent != releases):
        raise RuntimeError('Previous release is outside this instance')
    for ancestor in (releases, root, *root.parents):
        if not ancestor.is_dir() or not ancestor.stat().st_mode & 0o001:
            raise RuntimeError('Release ancestors require provisioned public traversal')
    for child in storage.rglob('*'):
        if child.is_symlink():
            raise RuntimeError('Persistent storage must not contain aliases')
    candidate = releases / release_id
    candidate.mkdir(exist_ok=False)
    archive = root / 'incoming' / (release_id + '.tar.gz')
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError('Unsafe archive member')
        bundle.extractall(candidate, members=members)
    # The worker keeps runtime/status files private, but nginx runs as a separate
    # principal. Expose only traversal into this release and its public assets.
    candidate.chmod(0o755)
    public = candidate / 'public'
    public.chmod(0o755)
    for asset in public.rglob('*'):
        asset.chmod(0o755 if asset.is_dir() else 0o644)
    if (candidate / '.env').exists() or (candidate / 'storage').exists():
        raise RuntimeError('Bundle must not contain environment or persistent storage')
    (candidate / '.env').symlink_to(shared / '.env')
    (candidate / 'storage').symlink_to(storage)
    for path in ('framework/cache/data', 'framework/sessions', 'framework/views', 'logs'):
        (storage / path).mkdir(parents=True, exist_ok=True)
    if (candidate / 'public/deployment-revision.txt').read_text().strip() != sha:
        raise RuntimeError('Bundle revision does not match the reviewed commit')
    if (candidate / 'public/deployment-release.txt').read_text().strip() != release_id:
        raise RuntimeError('Bundle release ID does not match the activation')
    if policy['branding']['enabled']:
        for key, asset in policy['branding'].items():
            if key != 'enabled' and not (candidate / 'public' / asset.lstrip('/')).is_file():
                raise RuntimeError('Release is missing its configured branding package')
    # Values are compared inside PHP, never printed. The database/user prefix is
    # deliberately separate from the consumer application's provisioned names.
    verification = r'''
require 'vendor/autoload.php';
$app = require 'bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$policy = json_decode($argv[4], true, flags: JSON_THROW_ON_ERROR);
$c = config('database.connections.'.config('database.default'));
$brandingValid = true;
foreach ($policy['branding'] as $key => $expected) {
    $brandingValid = $brandingValid && config('branding.'.$key) === $expected;
}
$valid = config('database.default') === 'mysql'
    && empty($c['url'])
    && ($c['database'] ?? null) === $argv[1]
    && ($c['username'] ?? null) === $policy['database_user']
    && rtrim(config('app.url', ''), '/') === $argv[2]
    && config('app.env') === $argv[3]
    && config('app.key')
    && config('app.name') === $policy['application_name']
    && $brandingValid
    && config('session.driver') === 'database'
    && in_array(config('session.connection'), [null, 'mysql'], true)
    && config('cache.default') === 'database'
    && in_array(config('cache.stores.database.connection'), [null, 'mysql'], true)
    && config('queue.default') === 'database'
    && in_array(config('queue.connections.database.connection'), [null, 'mysql'], true)
    && config('session.domain') === null
    && str_starts_with(config('session.cookie', ''), 'auth_manager_');
exit($valid ? 0 : 1);
'''
    run('php', '-r', verification, database, url,
        'production' if environment == 'prod' else 'staging', json.dumps(policy), cwd=candidate)
    # Only reviewed backward-compatible migrations are eligible: failure here
    # leaves the old current symlink untouched. Schema rollback is never automatic.
    run('php', 'artisan', 'migrate', '--force', '--no-interaction', cwd=candidate)
    for command in ('config:cache', 'route:cache', 'view:cache'):
        run('php', 'artisan', command, cwd=candidate)
    try:
        point_current(root, candidate)
        health(url, sha, release_id)
        restart_queue()
        if on_success is not None:
            on_success()
    except BaseException:
        ignore_termination()
        if previous is not None:
            point_current(root, previous)
            restart_queue()
            health(url, (previous / 'public/deployment-revision.txt').read_text().strip(), previous.name)
        else:
            try:
                run('sudo', '-n', '/usr/bin/systemctl', 'stop', 'auth-manager-queue.service')
            finally:
                current.unlink()
        raise


def restart_queue():
    # Fixed provisioned unit only; no app service or caller-selected command.
    run('sudo', '-n', '/usr/bin/systemctl', 'restart', 'auth-manager-queue.service')
    run('sudo', '-n', '/usr/bin/systemctl', 'is-active', '--quiet', 'auth-manager-queue.service')


def status_path(root, release_id):
    return Path(root) / 'incoming' / (release_id + '.status.json')


def write_status(root, release_id, sha, state, engine_sha):
    root = validate_location(root, release_id, sha, engine_sha)
    path = status_path(root, release_id)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        json.dump(status_record(release_id, sha, state, engine_sha), handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def launch_worker(root, environment, release_id, sha, url, database, engine_sha):
    root = validate_target(root, environment, release_id, sha, url, database, engine_sha)
    engine = validate_engine(root, release_id, engine_sha)
    os.umask(0o077)
    # Reserving a release status prevents a duplicate launch after transport loss.
    with status_path(root, release_id).open('x') as handle:
        json.dump(status_record(release_id, sha, 'queued', engine_sha), handle)
    requested = False
    try:
        log = root / 'incoming' / (release_id + '.log')
        with log.open('x'):
            pass
        requested = True
        subprocess.run([
            'systemd-run', '--user', '--quiet', '--collect',
            '--unit=auth-manager-' + environment + '-' + release_id,
            '--property=Type=exec', '--property=RuntimeMaxSec=900',
            '--property=TimeoutStopSec=120', '--property=UMask=0077',
            '--property=StandardOutput=append:' + str(log),
            '--property=StandardError=append:' + str(log),
            sys.executable, str(engine), 'worker', '--root', str(root), '--environment', environment,
            '--release-id', release_id, '--app-sha', sha, '--engine-sha', engine_sha,
            '--url', url, '--database', database,
        ], check=True, stdin=subprocess.DEVNULL, timeout=30)
    except OSError:
        # exec/spawn failed locally: no manager acknowledgement is ambiguous.
        write_status(root, release_id, sha, 'failed', engine_sha)
        raise
    except BaseException:
        # Once the manager has been contacted, timeout/nonzero exit can be
        # ambiguous: the independent worker may already be running or committed.
        # Only the worker may publish terminal status after that point.
        if not requested:
            write_status(root, release_id, sha, 'failed', engine_sha)
        raise
    print('Detached activation launched; poll the persisted release status')


def ignore_termination():
    while True:
        try:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            return
        except InterruptedError:
            continue
        except (OSError, ValueError):
            # If disposition changes fail, block delivery for rollback and exit.
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
            return


def publish_failure(root, release_id, sha, engine_sha):
    # Rollback has already completed by the time this runs. A repeated stop signal
    # (a second manual stop while rollback finished) must not leave the persisted
    # state at 'running': stop honouring SIGTERM first, and if the handler still
    # fires in the instant before that takes effect, retry the write rather than
    # exit without a terminal status. Failing to change the disposition is not a
    # reason to skip the write.
    while True:
        try:
            try:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            except (OSError, ValueError):
                pass
            write_status(root, release_id, sha, 'failed', engine_sha)
            return
        except InterruptedError:
            continue


def worker(root, environment, release_id, sha, url, database, engine_sha):
    root = validate_location(root, release_id, sha, engine_sha)
    validate_engine(root, release_id, engine_sha)
    def terminate(_signal, _frame):
        raise InterruptedError('Activation service was interrupted')
    committed = False
    def complete():
        nonlocal committed
        # Health is verified. Finish this short commit or its I/O-failure rollback
        # without interruption; success publication must be the last fallible step.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        write_status(root, release_id, sha, 'succeeded', engine_sha)
        committed = True
    try:
        os.umask(0o077)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, terminate)
        root = validate_target(root, environment, release_id, sha, url, database, engine_sha)
        write_status(root, release_id, sha, 'running', engine_sha)
        deploy(root, environment, release_id, sha, url, database, engine_sha, on_success=complete)
    except BaseException:
        if not committed:
            publish_failure(root, release_id, sha, engine_sha)
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['start', 'worker'])
    for name in ('root', 'environment', 'release-id', 'engine-sha', 'url', 'database'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--app-sha', dest='sha', required=True)
    args = vars(parser.parse_args())
    mode = args.pop('mode')
    (launch_worker if mode == 'start' else worker)(**args)
