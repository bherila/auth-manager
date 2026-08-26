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

    public function test_deployment_installs_and_verifies_the_scheduler_without_replacing_other_cron_entries(): void
    {
        $workflow = file_get_contents(__DIR__.'/../../.github/workflows/ci.yml');
        $this->assertIsString($workflow);

        $this->assertStringContainsString('- name: Install and verify Laravel scheduler cron', $workflow);
        $this->assertStringContainsString('existing="$(crontab -l 2>/dev/null || true)"', $workflow);
        $this->assertStringContainsString('artisan schedule:run > /dev/null 2>&1', $workflow);
        $this->assertSame(2, substr_count($workflow, 'grep -Fqx "$scheduler_line"'));
        $this->assertStringContainsString('{ printf', $workflow);
        $this->assertStringContainsString('| crontab -', $workflow);
        $this->assertGreaterThanOrEqual(2, substr_count($workflow, 'crontab -l'));
    }
}
