<?php

namespace Tests\Feature;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class ManageApplicationRegistrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_registers_updates_and_shows_an_entry_with_the_registry_rules_and_audit(): void
    {
        $client = $this->client('Example Client');
        $other = $this->client('Other Client');

        $this->artisan('auth-manager:application', ['key' => 'example-app'])->assertExitCode(1);
        $this->artisan('auth-manager:application', ['key' => 'example-app', '--name' => 'Example Application',
            '--launch-url' => 'https://app.example.test', '--client' => ['Example Client']])
            ->expectsOutputToContain('Registered example-app.')->assertExitCode(0);

        $application = RegisteredApplication::query()->where('key', 'example-app')->firstOrFail();
        $this->assertTrue($application->enabled);
        $this->assertSame([$client->getKey()], $application->clients->modelKeys());
        $this->assertSame('console', AuthAuditLog::query()->where('event', 'application_registered')->value('auth_method'));

        $this->artisan('auth-manager:application', ['key' => 'example-app', '--client' => [$other->getKey()], '--disable' => true])
            ->expectsOutputToContain('Updated example-app.')->assertExitCode(0);
        $application->refresh()->load('clients');
        $this->assertFalse($application->enabled);
        $this->assertSame([$other->getKey()], $application->clients->modelKeys());
        $this->assertSame('Example Application', $application->name);

        $this->artisan('auth-manager:application', ['key' => 'example-app'])->expectsOutputToContain('Other Client')->assertExitCode(0);
    }

    public function test_refuses_what_the_registry_page_refuses(): void
    {
        $this->client('Revoked Client', ['revoked' => true]);
        $this->client('Twin');
        $this->client('Twin');

        $base = ['key' => 'example-app', '--name' => 'Example Application', '--launch-url' => 'https://app.example.test'];
        $this->artisan('auth-manager:application', [...$base, '--launch-url' => 'http://app.example.test'])
            ->expectsOutputToContain('absolute HTTPS URL')->assertExitCode(1);
        $this->artisan('auth-manager:application', [...$base, '--client' => ['Revoked Client']])
            ->expectsOutputToContain('Select only active static authorization-code clients')->assertExitCode(1);
        $this->artisan('auth-manager:application', [...$base, '--client' => ['Twin']])
            ->expectsOutputToContain('More than one OAuth client is named Twin')->assertExitCode(1);
        $this->artisan('auth-manager:application', [...$base, '--client' => ['Missing']])->assertExitCode(1);
        $this->artisan('auth-manager:application', ['key' => 'Bad_Key', '--name' => 'X', '--launch-url' => 'https://app.example.test'])->assertExitCode(1);
        $this->artisan('auth-manager:application', [...$base, '--enable' => true, '--disable' => true])->assertExitCode(2);

        $this->assertSame(0, RegisteredApplication::query()->count());
        $this->assertSame(0, AuthAuditLog::query()->where('event', 'application_registered')->count());
    }

    private function client(string $name, array $attributes = []): PassportClient
    {
        return PassportClient::create([
            'id' => (string) Str::uuid(), 'name' => $name, 'secret' => 'synthetic-secret',
            'redirect_uris' => ['https://static.example.test/oauth/callback'],
            'grant_types' => ['authorization_code'], 'revoked' => false,
            ...$attributes,
        ]);
    }
}
