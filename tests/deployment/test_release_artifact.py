import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/release/build-artifact.sh'


def gnu_tar_available():
    for candidate in ('gtar', 'tar'):
        binary = shutil.which(candidate)
        if binary is None:
            continue
        version = subprocess.run([binary, '--version'], capture_output=True, text=True)
        if 'GNU tar' in version.stdout:
            return True
    return False


# Stand-ins for the dependency and asset builds. They write what the real tools
# would, plus whatever a test asks for through the environment.
COMPOSER = r'''#!/usr/bin/env bash
set -euo pipefail
case " $* " in *' --no-dev '*' --optimize-autoloader '*) ;; *) echo "unexpected composer arguments: $*" >&2; exit 2 ;; esac
mkdir -p vendor/composer vendor/example/package
printf '<?php // autoload\n' >vendor/autoload.php
printf '<?php // package\n' >vendor/example/package/Package.php
printf 'SYNTHETIC=1\n' >vendor/example/package/.env
mkdir -p bootstrap/cache && printf '<?php return [];\n' >bootstrap/cache/packages.php
if [ -n "${FIXTURE_SYMLINK:-}" ]; then ln -s ../autoload.php vendor/example/package/link.php; fi
if [ -n "${FIXTURE_CONFIG_CACHE:-}" ]; then printf '<?php return [];\n' >bootstrap/cache/config.php; fi
'''

PNPM = r'''#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'install --frozen-lockfile') mkdir -p node_modules/example && touch node_modules/example/index.js ;;
  'run build') mkdir -p public/build/assets public/branding
               printf '{}\n' >public/build/manifest.json
               printf 'body{}\n' >public/build/assets/app.css
               printf 'private\n' >public/branding/logo.svg ;;
  *) echo "unexpected pnpm arguments: $*" >&2; exit 2 ;;
esac
'''


@unittest.skipUnless(gnu_tar_available(), 'GNU tar is required')
class ReleaseArtifactTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository = self.root / 'repository'
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        for name, body in (('composer', COMPOSER), ('pnpm', PNPM)):
            (self.tools / name).write_text(body)
            (self.tools / name).chmod(0o755)

        files = {
            'app/Example.php': '<?php // synthetic application',
            'bootstrap/app.php': '<?php // bootstrap',
            'bootstrap/cache/.gitignore': '*\n!.gitignore\n',
            'config/app.php': '<?php return [];',
            'database/migrations/0001_example.php': '<?php // migration',
            'public/index.php': '<?php // front controller',
            'resources/views/example.blade.php': 'example',
            'routes/web.php': '<?php // routes',
            'storage/app/.gitignore': '*\n',
            'tests/ExampleTest.php': '<?php // test',
            '.github/workflows/ci.yml': 'name: ci\n',
            '.env.example': 'APP_NAME=Example\n',
            'composer.json': '{}\n',
            'composer.lock': '{}\n',
            'package.json': '{}\n',
            'artisan': '#!/usr/bin/env php\n<?php // artisan\n',
        }
        for relative, contents in files.items():
            path = self.repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        (self.repository / 'artisan').chmod(0o755)

        self.git('init', '--quiet')
        self.git('add', '--all')
        self.git('-c', 'user.name=Example', '-c', 'user.email=build@example.test',
                 'commit', '--quiet', '--message', 'Synthetic release fixture',
                 env={'GIT_COMMITTER_DATE': '2026-01-02T03:04:05Z', 'GIT_AUTHOR_DATE': '2026-01-02T03:04:05Z'})
        self.commit = self.git('rev-parse', 'HEAD').strip()

    def git(self, *arguments, env=None):
        return subprocess.run(['git', *arguments], cwd=self.repository, check=True,
                              capture_output=True, text=True, env={**os.environ, **(env or {})}).stdout

    def build(self, output, tag='v1.2.3', umask=0o022, **fixture):
        environment = {**os.environ, 'PATH': f'{self.tools}{os.pathsep}{os.environ["PATH"]}', **fixture}
        previous = os.umask(umask)
        try:
            return subprocess.run(['bash', str(SCRIPT), tag, str(output)], cwd=self.repository,
                                  capture_output=True, text=True, env=environment)
        finally:
            os.umask(previous)

    def test_the_archive_holds_the_deployable_tree_and_nothing_private(self):
        result = self.build(self.root / 'out')
        self.assertEqual(result.returncode, 0, result.stderr)

        archive = self.root / 'out/auth-manager-v1.2.3.tar.gz'
        with tarfile.open(archive) as bundle:
            members = {member.name: member for member in bundle.getmembers()}
            revision = bundle.extractfile('public/deployment-revision.txt').read().decode()

        self.assertEqual(revision, self.commit + '\n')
        for expected in ('artisan', 'app/Example.php', 'bootstrap/cache/packages.php', 'config/app.php',
                         'database/migrations/0001_example.php', 'public/build/manifest.json',
                         'resources/views/example.blade.php', 'routes/web.php', 'vendor/autoload.php',
                         'composer.json', 'composer.lock'):
            self.assertIn(expected, members)
        for name in members:
            self.assertFalse(name.startswith(('storage', 'tests', 'node_modules', '.github', 'public/branding', '/')), name)
            self.assertNotIn('..', Path(name).parts)
            self.assertNotEqual(Path(name).name, '.env', name)
        self.assertNotIn('.env.example', members)
        self.assertNotIn('package.json', members)

        for member in members.values():
            self.assertTrue(member.isfile() or member.isdir(), member.name)
            self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, '', ''), member.name)
            self.assertEqual(member.mtime, 1767323045, member.name)
        self.assertEqual(members['artisan'].mode & 0o777, 0o755)
        self.assertEqual(members['app/Example.php'].mode & 0o777, 0o644)
        self.assertEqual(members['vendor'].mode & 0o777, 0o755)

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual((self.root / 'out/SHA256SUMS').read_text(), f'{digest}  auth-manager-v1.2.3.tar.gz\n')

    def test_rebuilding_the_same_commit_is_byte_identical_whatever_the_tag_or_umask(self):
        first = self.build(self.root / 'first', tag='v1.2.3', umask=0o022)
        second = self.build(self.root / 'second', tag='v1.2.3-rc.1', umask=0o077)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)

        self.assertEqual((self.root / 'first/auth-manager-v1.2.3.tar.gz').read_bytes(),
                         (self.root / 'second/auth-manager-v1.2.3-rc.1.tar.gz').read_bytes())

    def test_untracked_working_tree_files_never_reach_the_archive(self):
        (self.repository / '.env').write_text('SECRET=synthetic\n')
        (self.repository / 'app/Untracked.php').write_text('<?php // untracked')

        result = self.build(self.root / 'out')
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.root / 'out/auth-manager-v1.2.3.tar.gz') as bundle:
            names = bundle.getnames()
        self.assertNotIn('app/Untracked.php', names)
        self.assertNotIn('.env', names)

    def test_it_refuses_symlinks_and_configuration_caches(self):
        for fixture, message in (({'FIXTURE_SYMLINK': '1'}, 'symlink'),
                                 ({'FIXTURE_CONFIG_CACHE': '1'}, 'bootstrap/cache/config.php')):
            output = self.root / ('out-' + next(iter(fixture)))
            result = self.build(output, **fixture)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
            self.assertFalse((output / 'SHA256SUMS').exists())

    def test_it_rejects_tags_that_are_not_versions(self):
        for tag in ('main', 'v1.2', '1.2.3', 'v1.2.3;id', 'v1.2.3-'):
            result = self.build(self.root / 'out', tag=tag)
            self.assertNotEqual(result.returncode, 0, tag)
            self.assertIn('TAG must look like', result.stderr)


if __name__ == '__main__':
    unittest.main()


SOURCE_SCRIPT = SCRIPT.with_name('build-source-archive.sh')


@unittest.skipUnless(gnu_tar_available(), 'GNU tar is required')
class SourceArchiveTest(ReleaseArtifactTest):
    """Reuses the synthetic repository of the deploy-tree tests."""

    def build_source(self, output, tag='v1.2.3'):
        environment = {**os.environ, 'PATH': f'{self.tools}{os.pathsep}{os.environ["PATH"]}'}
        return subprocess.run(['bash', str(SOURCE_SCRIPT), tag, str(output)], cwd=self.repository,
                              capture_output=True, text=True, env=environment)

    def test_the_source_archive_is_installable_and_has_no_dependencies(self):
        import json
        import zipfile

        result = self.build_source(self.root / 'src')
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = self.root / 'src/auth-manager-source-v1.2.3.zip'
        with zipfile.ZipFile(archive) as bundle:
            names = set(bundle.namelist())
            manifest = json.loads(bundle.read('composer.json'))

        self.assertEqual(manifest['version'], '1.2.3')
        for expected in ('composer.json', 'artisan', 'app/Example.php', 'public/build/manifest.json',
                         'public/deployment-revision.txt', 'tests/ExampleTest.php'):
            self.assertIn(expected, names)
        for name in names:
            self.assertFalse(name.startswith(('vendor', 'node_modules', 'storage', '.github', 'public/branding', '/')), name)
            self.assertNotEqual(Path(name).name, '.env', name)

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual((self.root / 'src/SHA256SUMS-source').read_text(),
                         f'{digest}  auth-manager-source-v1.2.3.zip\n')

    def test_the_source_archive_is_reproducible(self):
        self.assertEqual(self.build_source(self.root / 'a').returncode, 0)
        self.assertEqual(self.build_source(self.root / 'b').returncode, 0)
        self.assertEqual((self.root / 'a/SHA256SUMS-source').read_text(), (self.root / 'b/SHA256SUMS-source').read_text())
