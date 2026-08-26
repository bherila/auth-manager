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
}
