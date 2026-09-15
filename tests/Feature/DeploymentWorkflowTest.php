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

    public function test_both_deployments_pin_the_shared_action_and_migrate_before_upload(): void
    {
        $this->assertSame(2, preg_match_all(
            '/uses: bherila\/shared-cpanel-deployment@[a-f0-9]{40} # v1\.1\.0/',
            $this->workflow,
        ));
        $this->assertSame(2, substr_count($this->workflow, 'migration-order: before-upload'));
        $this->assertSame(2, substr_count($this->workflow, 'run-migrations: true'));
        $this->assertStringNotContainsString('artisan migrate --force', $this->workflow);
        $this->assertStringNotContainsString(':~/auth-manager/database/migrations/', $this->workflow);
    }

    public function test_each_deployment_asserts_its_server_owned_profile_and_route(): void
    {
        $primary = $this->job('  deploy:', '  deploy_resource:');
        $resource = $this->job('  deploy_resource:');

        $this->assertStringContainsString('environment: web1', $primary);
        $this->assertStringContainsString("test \"\$DEPLOY_PROFILE\" = 'bherila'", $primary);
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
