<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;

class ReleaseWorkflowTest extends TestCase
{
    private const ROOT = __DIR__.'/../..';

    private string $workflow;

    protected function setUp(): void
    {
        parent::setUp();

        $this->workflow = $this->read('.github/workflows/release.yml');
    }

    public function test_it_runs_only_for_version_tags_and_manual_reruns_in_the_canonical_repository(): void
    {
        $triggers = $this->between("\non:\n", "\npermissions:");
        $this->assertStringContainsString("  push:\n    tags:\n      - 'v*'\n", $triggers);
        $this->assertStringNotContainsString('branches', $triggers);
        $this->assertStringContainsString("  workflow_dispatch:\n    inputs:\n      tag:\n", $triggers);

        foreach (['pull_request', 'pull_request_target', 'workflow_run', 'schedule', 'repository_dispatch'] as $event) {
            $this->assertStringNotContainsString($event, $triggers, $event);
        }
        $this->assertStringNotContainsString('pull_request', $this->workflow);

        $resolve = $this->job('resolve');
        $this->assertStringContainsString("github.repository == 'bherila/auth-manager'", $resolve);
        $this->assertStringContainsString("(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v'))", $resolve);
        $this->assertStringContainsString("(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')", $resolve);
        $this->assertStringContainsString('git merge-base --is-ancestor "$commit" refs/remotes/origin/main', $resolve);
    }

    public function test_every_later_job_depends_on_the_guarded_job_and_cannot_bypass_it(): void
    {
        $this->assertSame(['resolve', 'verify', 'build', 'publish', 'notify'], array_keys($this->jobs()));

        $needs = [
            'verify' => 'needs: resolve',
            'build' => 'needs: [resolve, verify]',
            'publish' => 'needs: [resolve, build]',
            'notify' => 'needs: [resolve, publish]',
        ];
        foreach ($needs as $job => $dependency) {
            $block = $this->job($job);
            $this->assertStringContainsString("    $dependency\n", $block, $job);
            // A job condition would replace the implicit success() check on its dependencies.
            $this->assertDoesNotMatchRegularExpression('/^    if:/m', $block, $job);
        }

        foreach (['always()', 'cancelled()', 'failure()', 'continue-on-error'] as $bypass) {
            $this->assertStringNotContainsString($bypass, $this->workflow, $bypass);
        }
    }

    public function test_permissions_are_empty_by_default_and_granted_only_where_needed(): void
    {
        $this->assertStringContainsString("\npermissions: {}\n", $this->workflow);

        $expected = [
            'resolve' => "    permissions:\n      contents: read\n",
            'verify' => "    permissions:\n      contents: read\n",
            'build' => "    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n",
            'publish' => "    permissions:\n      contents: write\n",
            'notify' => "    permissions: {}\n",
        ];
        foreach ($expected as $job => $permissions) {
            $block = $this->job($job);
            $this->assertStringContainsString($permissions, $block, $job);
            $this->assertSame(1, substr_count($block, '    permissions:'), $job);
        }

        $this->assertSame(1, substr_count($this->workflow, 'id-token: write'));
        $this->assertSame(1, substr_count($this->workflow, 'attestations: write'));
        $this->assertSame(1, substr_count($this->workflow, 'contents: write'));
        $this->assertStringNotContainsString('write-all', $this->workflow);
    }

    public function test_every_action_in_every_workflow_is_pinned_to_a_full_commit_sha(): void
    {
        foreach (glob(self::ROOT.'/.github/workflows/*.yml') ?: [] as $path) {
            $contents = file_get_contents($path);
            $this->assertIsString($contents);
            preg_match_all('/^\s*(?:-\s+)?uses:\s*(\S+)/m', $contents, $matches);
            foreach ($matches[1] as $action) {
                $this->assertMatchesRegularExpression('/^[\w.-]+\/[\w.\/-]+@[0-9a-f]{40}$/', $action, basename($path).': '.$action);
            }
        }

        $this->assertStringContainsString(
            'uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2',
            $this->job('build'),
        );
        $this->assertStringContainsString(
            '${{ runner.temp }}/release/auth-manager-${{ needs.resolve.outputs.tag }}.tar.gz',
            $this->job('build'),
        );
        $this->assertStringContainsString(
            '${{ runner.temp }}/release/auth-manager-source-${{ needs.resolve.outputs.tag }}.zip',
            $this->job('build'),
        );
        $this->assertStringContainsString(
            'run: bash scripts/release/build-source-archive.sh "$TAG" "$RUNNER_TEMP/release" "$COMMIT"',
            $this->job('build'),
        );
        $this->assertStringContainsString(
            '"$name" SHA256SUMS "$source_name" SHA256SUMS-source',
            $this->job('publish'),
        );
    }

    public function test_scripts_receive_untrusted_values_only_through_the_environment(): void
    {
        foreach ($this->runScripts() as $index => $script) {
            $this->assertStringNotContainsString('${{', $script, "run script $index interpolates an expression");
            $this->assertDoesNotMatchRegularExpression('/^\s*set -[a-z]*x/m', $script, "run script $index traces commands");
        }

        $this->assertSame(
            substr_count($this->workflow, 'uses: actions/checkout@'),
            substr_count($this->workflow, 'persist-credentials: false'),
        );
    }

    public function test_the_published_release_carries_the_checksum_commit_and_verification_command(): void
    {
        $publish = $this->job('publish');

        $this->assertStringContainsString('run: bash scripts/release/build-artifact.sh "$TAG" "$RUNNER_TEMP/release" "$COMMIT"', $this->job('build'));
        $this->assertStringContainsString('sha256sum --check --strict SHA256SUMS', $publish);
        $this->assertStringContainsString('echo "Commit: \`$COMMIT\`"', $publish);
        $this->assertStringContainsString('SHA-256: \`$SHA256\`', $publish);
        $this->assertStringContainsString('echo "gh attestation verify $name --repo bherila/auth-manager"', $publish);
        $this->assertStringContainsString('gh release create "$TAG" --verify-tag --draft', $publish);
        $this->assertStringContainsString('"$name" SHA256SUMS', $publish);
        $this->assertStringContainsString('gh release edit "$TAG" --draft=false', $publish);
        // A published asset is never replaced or deleted.
        $this->assertStringNotContainsString('--clobber', $publish);
        $this->assertStringNotContainsString('--cleanup-tag', $publish);
        $this->assertStringContainsString('if [ "$state" = draft ]; then', $publish);
        // The tag is re-resolved after the build, so a moved tag publishes nothing.
        $this->assertStringContainsString('if [ "$object" != "$COMMIT" ]; then', $publish);
    }

    public function test_consumer_notification_is_optional_and_never_logs_its_configuration(): void
    {
        $notify = $this->job('notify');

        $this->assertStringContainsString('RELEASE_CONSUMERS: ${{ secrets.RELEASE_CONSUMERS }}', $notify);
        $this->assertStringContainsString('RELEASE_DISPATCH_TOKEN: ${{ secrets.RELEASE_DISPATCH_TOKEN }}', $notify);
        $this->assertSame(2, substr_count($this->workflow, '${{ secrets.'));
        $this->assertStringContainsString(
            'if [ -z "$RELEASE_CONSUMERS" ] || [ -z "$RELEASE_DISPATCH_TOKEN" ]; then',
            $notify,
        );
        $this->assertStringContainsString('{event_type: "auth-manager-release", client_payload: {tag: $tag, sha256: $sha256, commit: $commit}}', $notify);
        $this->assertStringContainsString('echo "::add-mask::$consumer"', $notify);
        // The token reaches curl through a private header file, never its argument list.
        $this->assertStringContainsString("(umask 077 && printf 'Authorization: Bearer %s\\n' \"\$RELEASE_DISPATCH_TOKEN\" >\"\$headers\")", $notify);
        $this->assertStringContainsString('--header @"$headers"', $notify);
        $this->assertSame(2, substr_count($notify, '$RELEASE_DISPATCH_TOKEN'));

        foreach (['echo "$RELEASE_CONSUMERS', 'echo "$consumer"', 'echo "$RELEASE_DISPATCH_TOKEN', 'curl --verbose', 'curl -v'] as $leak) {
            $this->assertStringNotContainsString($leak, $notify, $leak);
        }
    }

    public function test_the_artifact_packages_what_the_deploy_jobs_upload_reproducibly(): void
    {
        $script = $this->read('scripts/release/build-artifact.sh');
        $ci = $this->read('.github/workflows/ci.yml');

        $this->assertStringContainsString('composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader', $script);
        $this->assertStringContainsString('pnpm install --frozen-lockfile', $script);
        $this->assertStringContainsString('pnpm run build', $script);
        $this->assertStringContainsString('git -C "$repository" archive --format=tar "$commit"', $script);

        // The deploy jobs upload the shared action's default paths. If they ever
        // choose their own, the artifact's list has to be revisited with them.
        $this->assertDoesNotMatchRegularExpression('/^\s+paths:/m', $ci);
        $this->assertStringContainsString(
            'paths=(app bootstrap config database public resources routes vendor artisan composer.json composer.lock)',
            $script,
        );
        // Every exclusion the deploy jobs add is excluded from the artifact too.
        $this->assertSame(2, substr_count($ci, "excludes: |\n            .db-credentials\n            /public/branding/\n"));
        $this->assertStringContainsString(
            'excludes=(.env .deploy-release .db-credentials public/branding public/hot public/storage)',
            $script,
        );

        foreach (['--sort=name', '--mtime="@$epoch"', '--owner=0 --group=0 --numeric-owner', '--hard-dereference', 'gzip -n'] as $flag) {
            $this->assertStringContainsString($flag, $script, $flag);
        }

        $this->assertStringContainsString('bash scripts/release/build-artifact.sh v0.0.0-ci "$RUNNER_TEMP/first"', $ci);
        $this->assertStringContainsString('cmp "$RUNNER_TEMP/first/SHA256SUMS" "$RUNNER_TEMP/second/SHA256SUMS"', $ci);
    }

    public function test_the_source_archive_excludes_dependencies_and_is_built_reproducibly(): void
    {
        $script = $this->read('scripts/release/build-source-archive.sh');
        $ci = $this->read('.github/workflows/ci.yml');

        $this->assertStringContainsString('pnpm run build', $script);
        $this->assertStringNotContainsString('composer install', $script);
        $this->assertStringContainsString("skipped_directories = {'vendor', 'node_modules', '.git', '.github', 'storage'}", $script);
        $this->assertStringContainsString("manifest['version'] = tag[1:]", $script);
        $this->assertStringContainsString('bash scripts/release/build-source-archive.sh v0.0.0-ci "$RUNNER_TEMP/first"', $ci);
        $this->assertStringContainsString('cmp "$RUNNER_TEMP/first/SHA256SUMS-source" "$RUNNER_TEMP/second/SHA256SUMS-source"', $ci);
    }

    /**
     * @return array<string, string>
     */
    private function jobs(): array
    {
        $body = substr($this->workflow, (int) strpos($this->workflow, "\njobs:\n") + 7);
        $parts = preg_split('/^  ([a-z_]+):\n/m', $body, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
        $this->assertIsArray($parts);

        $jobs = [];
        for ($index = 0; $index + 1 < count($parts); $index += 2) {
            $jobs[$parts[$index]] = $parts[$index + 1];
        }

        return $jobs;
    }

    private function job(string $name): string
    {
        $jobs = $this->jobs();
        $this->assertArrayHasKey($name, $jobs);

        return $jobs[$name];
    }

    /**
     * @return list<string>
     */
    private function runScripts(): array
    {
        $scripts = [];
        $lines = explode("\n", $this->workflow);
        foreach ($lines as $number => $line) {
            if (! preg_match('/^(\s*)(?:-\s+)?run:\s*(.*)$/', $line, $match)) {
                continue;
            }
            if ($match[2] !== '|') {
                $scripts[] = $match[2];

                continue;
            }
            $indent = strlen($match[1]);
            $script = '';
            for ($next = $number + 1; $next < count($lines); $next++) {
                $candidate = $lines[$next];
                if (trim($candidate) !== '' && strlen($candidate) - strlen(ltrim($candidate)) <= $indent) {
                    break;
                }
                $script .= $candidate."\n";
            }
            $scripts[] = $script;
        }
        $this->assertNotEmpty($scripts);

        return $scripts;
    }

    private function between(string $start, string $end): string
    {
        $offset = strpos($this->workflow, $start);
        $this->assertNotFalse($offset);
        $endOffset = strpos($this->workflow, $end, $offset + strlen($start));
        $this->assertNotFalse($endOffset);

        return substr($this->workflow, $offset, $endOffset - $offset);
    }

    private function read(string $path): string
    {
        $contents = file_get_contents(self::ROOT.'/'.$path);
        $this->assertIsString($contents);

        return $contents;
    }
}
