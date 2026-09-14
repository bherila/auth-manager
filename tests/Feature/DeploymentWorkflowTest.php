<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;

class DeploymentWorkflowTest extends TestCase
{
    public function test_database_migrations_run_before_application_code_is_deployed(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $migrationStep = strpos($workflow, '- name: Apply backward-compatible database migrations');
        $applicationDeployStep = strpos($workflow, '- name: Deploy application with guarded rsync');
        $migrationCommand = strpos($workflow, 'artisan migrate --force');

        $this->assertNotFalse($migrationStep);
        $this->assertNotFalse($applicationDeployStep);
        $this->assertNotFalse($migrationCommand);
        $this->assertLessThan($applicationDeployStep, $migrationStep);
        $this->assertLessThan($applicationDeployStep, $migrationCommand);
    }

    public function test_resource_deployment_is_explicit_and_migration_first(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $resourceJob = strpos($workflow, '  deploy_resource:');
        $this->assertNotFalse($resourceJob);

        $resourceWorkflow = substr($workflow, $resourceJob);
        $this->assertStringContainsString('environment: resource-web1', $resourceWorkflow);
        $this->assertStringContainsString('DEPLOY_PROFILE: ${{ vars.AUTH_MANAGER_PROFILE }}', $resourceWorkflow);
        $this->assertStringContainsString('DEPLOY_SITE_URL: ${{ vars.SITE_URL }}', $resourceWorkflow);
        $this->assertStringContainsString("test \"\$DEPLOY_PROFILE\" = 'resource'", $resourceWorkflow);
        $this->assertStringContainsString(':~/auth-manager/database/migrations/', $resourceWorkflow);
        $this->assertStringContainsString(':~/auth-manager/', $resourceWorkflow);
        $this->assertStringContainsString('/opt/cpanel/ea-php85/root/usr/bin/php artisan', $resourceWorkflow);

        $migrationStep = strpos($resourceWorkflow, '- name: Apply backward-compatible database migrations');
        $applicationDeployStep = strpos($resourceWorkflow, '- name: Deploy application with guarded rsync');
        $migrationCommand = strpos($resourceWorkflow, 'artisan migrate --force');

        $this->assertNotFalse($migrationStep);
        $this->assertNotFalse($applicationDeployStep);
        $this->assertNotFalse($migrationCommand);
        $this->assertLessThan($applicationDeployStep, $migrationStep);
        $this->assertLessThan($applicationDeployStep, $migrationCommand);
    }

    /**
     * Both deployments install the scheduler through the shared-crontab script, never by text matching.
     *
     * The account crontab is shared with other applications. Matching the scheduler line by exact text
     * and appending it when "missing" duplicated the scheduler once a hand edit changed the line, and
     * writing back `$(crontab -l || true)` plus one line would empty the crontab on a failed read.
     */
    public function test_deployment_installs_the_scheduler_through_the_shared_crontab_script(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $this->assertSame(2, substr_count($workflow, '- name: Install and verify Laravel scheduler cron'));
        $this->assertSame(2, substr_count($workflow, 'bash scripts/deploy/test-install-cron.sh'));
        $this->assertSame(2, substr_count($workflow, '< scripts/deploy/install-cron.sh'));
        $this->assertSame(2, substr_count(
            $workflow,
            '\'* * * * * cd "$HOME/auth-manager" && /opt/cpanel/ea-php85/root/usr/bin/php -d memory_limit=1G artisan schedule:run > /dev/null 2>&1 # JOB:auth-manager-scheduler\'',
        ));

        $this->assertStringNotContainsString('crontab -l 2>/dev/null || true', $workflow);
        $this->assertStringNotContainsString('| crontab -', $workflow);
        $this->assertStringNotContainsString('grep -Fqx "$scheduler_line"', $workflow);

        $harness = strpos($workflow, 'bash scripts/deploy/test-install-cron.sh');
        $install = strpos($workflow, '< scripts/deploy/install-cron.sh');
        $this->assertLessThan($install, $harness, 'The harness must run before the crontab is touched.');
    }

    public function test_the_crontab_script_refuses_unsafe_rewrites(): void
    {
        $script = file_get_contents(__DIR__.'/../../scripts/deploy/install-cron.sh');
        $this->assertIsString($script);

        $this->assertStringContainsString('flock -w', $script);
        $this->assertStringContainsString('refusing to rewrite it', $script);
        $this->assertStringContainsString('crontab "$work/next"', $script);
        $this->assertStringContainsString('.crontab-backups', $script);
        $this->assertStringNotContainsString('| crontab -', $script);
    }

    /**
     * The harness runs the real script against a fake `crontab`: an empty crontab, a failed read,
     * replacing only this application's lines, idempotency, refused input, and quoting over ssh.
     */
    public function test_the_crontab_script_harness_passes(): void
    {
        exec('command -v bash', $found, $status);
        if ($status !== 0) {
            $this->markTestSkipped('bash is not available.');
        }

        exec('bash '.escapeshellarg(__DIR__.'/../../scripts/deploy/test-install-cron.sh').' 2>&1', $output, $status);

        $this->assertSame(0, $status, implode("\n", $output));
    }

    public function test_both_deployments_verify_the_web_handlers_php_limits(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $this->assertSame(2, substr_count($workflow, "- name: Verify the web handler's PHP version and memory limit"));
        $this->assertSame(2, substr_count($workflow, 'bash scripts/deploy/verify-web-php.sh'));
        $this->assertSame(2, substr_count($workflow, ' 8.5 1024M '));
    }
}
