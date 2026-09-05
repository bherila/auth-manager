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

    public function test_deployment_installs_and_verifies_the_scheduler_without_replacing_other_cron_entries(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $this->assertStringContainsString('- name: Install and verify Laravel scheduler cron', $workflow);
        $this->assertStringContainsString('existing="$(crontab -l 2>/dev/null || true)"', $workflow);
        $this->assertStringContainsString('artisan schedule:run > /dev/null 2>&1', $workflow);
        $this->assertSame(2, substr_count($workflow, '- name: Install and verify Laravel scheduler cron'));
        $this->assertSame(4, substr_count($workflow, 'grep -Fqx "$scheduler_line"'));
        $this->assertStringContainsString('{ printf', $workflow);
        $this->assertStringContainsString('| crontab -', $workflow);
        $this->assertGreaterThanOrEqual(4, substr_count($workflow, 'crontab -l'));
    }
}
