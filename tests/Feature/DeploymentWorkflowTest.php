<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;

class DeploymentWorkflowTest extends TestCase
{
    private string $workflow;

    protected function setUp(): void
    {
        parent::setUp();

        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);
        $this->workflow = $workflow;
    }

    public function test_both_deployments_pin_the_v2_action_and_use_atomic_releases(): void
    {
        $this->assertSame(2, preg_match_all(
            '/uses: bherila\/shared-cpanel-deployment@5798879af588e2c786357b69b314d89932b75803 # v2\.6\.0/',
            $this->workflow,
        ));
        $this->assertSame(2, preg_match_all('/uses: bherila\/shared-cpanel-deployment@[a-f0-9]{40}\b/', $this->workflow));
        $this->assertStringNotContainsString('migration-order', $this->workflow);
        $this->assertSame(3, substr_count($this->workflow, 'cancel-in-progress: false'));
        $this->assertSame(2, substr_count($this->workflow, 'run-migrations: true'));
        $this->assertStringNotContainsString('artisan migrate --force', $this->workflow);
        $this->assertStringNotContainsString(':~/auth-manager/database/migrations/', $this->workflow);

        foreach ([
            'deployment-mode: atomic',
            'atomic-layout: stable-directory',
            'persistent-paths: storage',
            'failure-policy: maintenance',
            'initial-live-commit: ${{ vars.ATOMIC_INITIAL_LIVE_COMMIT }}',
            'recovery-release-id: ${{ vars.ATOMIC_RECOVERY_RELEASE_ID }}',
            "operational-audit: 'true'",
            "runtime-audit: 'true'",
            'pre-migrate-script: scripts/deploy/pre-migrate.sh',
            // The action refuses to convert or update an existing application without a quiescence hook.
            'quiesce-script: scripts/deploy/quiesce.sh',
        ] as $setting) {
            $this->assertSame(2, substr_count($this->workflow, $setting), $setting);
        }
    }

    public function test_quiesce_hook_waits_for_this_applications_artisan_processes_and_ci_exercises_it(): void
    {
        $hook = file_get_contents(__DIR__.'/../../scripts/deploy/quiesce.sh');
        $this->assertIsString($hook);

        $this->assertStringContainsString('.deployments/auth-manager/releases/*) ;;', $hook);
        $this->assertStringContainsString('test "$stable_path" = auth-manager', $hook);
        $this->assertStringContainsString('mapfile -d', $hook);
        $this->assertStringContainsString('run: bash tests/deployment/test-deploy-hooks.sh', $this->workflow);
        $this->assertFileExists(__DIR__.'/../deployment/test-deploy-hooks.sh');
    }

    public function test_pre_migrate_hook_installs_release_local_credentials_and_checks_the_signing_pair(): void
    {
        $hook = file_get_contents(__DIR__.'/../../scripts/deploy/pre-migrate.sh');
        $this->assertIsString($hook);

        $this->assertStringContainsString('test "$stable_dir" = auth-manager', $hook);
        $this->assertStringContainsString('install -m 600 "$source_file" .db-credentials', $hook);
        $this->assertStringContainsString('test -s storage/app/private/oauth/oauth-private.key', $hook);
        $this->assertStringContainsString('test -s storage/app/private/oauth/oauth-public.key', $hook);
        foreach (['cat ', 'passport:keys', 'artisan ', 'rm '] as $forbidden) {
            $this->assertStringNotContainsString($forbidden, $hook);
        }
    }

    public function test_each_deployment_asserts_its_server_owned_profile_and_route(): void
    {
        $primary = $this->job('  deploy:', '  deploy_resource:');
        $resource = $this->job('  deploy_resource:');

        $this->assertStringContainsString('environment: web1', $primary);
        $this->assertStringContainsString("test \"\$DEPLOY_PROFILE\" = 'identity' || test \"\$DEPLOY_PROFILE\" = 'bherila'", $primary);
        $this->assertStringContainsString('environment: resource-web1', $resource);
        $this->assertStringContainsString("test \"\$DEPLOY_PROFILE\" = 'resource'", $resource);

        foreach ([$primary, $resource] as $job) {
            $this->assertStringContainsString('DEPLOY_PROFILE: ${{ vars.AUTH_MANAGER_PROFILE }}', $job);
            $this->assertStringContainsString('DEPLOY_SITE_URL: ${{ vars.SITE_URL }}', $job);
            $this->assertStringContainsString('site-url: ${{ env.DEPLOY_SITE_URL }}', $job);
            $this->assertStringContainsString('env-source: .config/auth-manager/deployment.env', $job);
            $this->assertStringContainsString('env-assert: AUTH_MANAGER_PROFILE=${{ env.DEPLOY_PROFILE }}', $job);
        }
    }

    public function test_deployments_run_only_for_a_push_to_main_of_the_canonical_repository(): void
    {
        $guard = "    if: \${{ !cancelled() && github.event_name == 'push' && github.repository == 'bherila/auth-manager' && github.ref == 'refs/heads/main' && needs.ci.result == 'success' && needs.mariadb.result == 'success' }}\n";

        $this->assertStringContainsString($guard, $this->job('  deploy:', '  deploy_resource:'));
        $this->assertStringContainsString($guard, $this->job('  deploy_resource:'));
        $this->assertSame(2, substr_count($this->workflow, $guard));
        // The production engine's tests gate the deploys they protect.
        $this->assertSame(2, substr_count($this->workflow, "    needs: [ci, mariadb]\n"));
        $this->assertStringNotContainsString('pull_request_target', $this->workflow);
        $this->assertStringContainsString("permissions:\n  contents: read\n", $this->workflow);
    }

    public function test_runtime_signing_keys_and_optional_private_branding_are_deploy_owned(): void
    {
        $this->assertSame(2, substr_count(
            $this->workflow,
            'passport-key-directory: storage/app/private/oauth',
        ));
        $this->assertSame(2, substr_count(
            $this->workflow,
            'branding-source: ${{ vars.BRANDING_SOURCE }}',
        ));
        $this->assertSame(2, substr_count($this->workflow, '/public/branding/'));
        $this->assertSame(2, substr_count($this->workflow, '.db-credentials'));
        $this->assertStringNotContainsString('passport:keys --force', $this->workflow);
        $this->assertStringNotContainsString('install-cron.sh', $this->workflow);
        $this->assertStringNotContainsString('verify-web-php.sh', $this->workflow);
        $this->assertStringNotContainsString('htaccess-append.txt', $this->workflow);
    }

    private function job(string $start, ?string $end = null): string
    {
        $offset = strpos($this->workflow, $start);
        $this->assertNotFalse($offset);

        if ($end === null) {
            return substr($this->workflow, $offset);
        }

        $endOffset = strpos($this->workflow, $end, $offset + strlen($start));
        $this->assertNotFalse($endOffset);

        return substr($this->workflow, $offset, $endOffset - $offset);
    }
}
