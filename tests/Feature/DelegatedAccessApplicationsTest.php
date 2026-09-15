<?php

namespace Tests\Feature;

use App\Support\DelegatedAccessApplications;
use InvalidArgumentException;
use Tests\TestCase;

class DelegatedAccessApplicationsTest extends TestCase
{
    public function test_valid_entries_become_the_transport_map(): void
    {
        $this->assertSame([
            'example-app' => ['endpoint' => 'https://app.example.test/application-access', 'contract_version' => 2],
            'other-app2' => ['endpoint' => 'https://other.example.test:8443/access', 'contract_version' => 1],
        ], DelegatedAccessApplications::parse(
            'example-app|https://app.example.test/application-access|2, other-app2 | https://other.example.test:8443/access | 1',
        ));
    }

    public function test_an_empty_or_unset_value_means_no_applications(): void
    {
        foreach ([null, '', '   '] as $value) {
            $this->assertSame([], DelegatedAccessApplications::parse($value));
        }
    }

    public function test_each_malformed_entry_class_is_refused(): void
    {
        $valid = 'https://app.example.test/access';
        $cases = [
            'non-string value' => true,
            'key only' => 'example-app',
            'missing version' => "example-app|{$valid}",
            'extra field' => "example-app|{$valid}|2|extra",
            'trailing empty entry' => "example-app|{$valid}|2,",
            'leading empty entry' => ",example-app|{$valid}|2",
            'empty key' => "|{$valid}|2",
            'uppercase key' => "Example-App|{$valid}|2",
            'key starting with a digit' => "1app|{$valid}|2",
            'key with an underscore' => "example_app|{$valid}|2",
            'key longer than 64 bytes' => 'a'.str_repeat('b', 64)."|{$valid}|2",
            'empty endpoint' => 'example-app||2',
            'relative endpoint' => 'example-app|app.example.test/access|2',
            'invalid host' => 'example-app|https://bad_host.example.test/access|2',
            'port zero' => 'example-app|https://app.example.test:0/access|2',
            'username' => 'example-app|https://user@app.example.test/access|2',
            'username and password' => 'example-app|https://user:password@app.example.test/access|2',
            'query' => 'example-app|https://app.example.test/access?tenant=one|2',
            'fragment' => 'example-app|https://app.example.test/access#top|2',
            'empty version' => "example-app|{$valid}|",
            'version zero' => "example-app|{$valid}|0",
            'unknown version' => "example-app|{$valid}|3",
            'padded version' => "example-app|{$valid}|01",
            'decimal version' => "example-app|{$valid}|2.0",
            'bad entry after a good one' => "example-app|{$valid}|2,other-app|{$valid}|9",
        ];

        foreach ($cases as $label => $value) {
            $this->assertRefused($value, $label);
        }
    }

    public function test_duplicate_keys_are_malformed_even_with_identical_entries(): void
    {
        $this->assertRefused('example-app|https://app.example.test/access|2,example-app|https://app.example.test/access|2', 'identical duplicate');
        $this->assertRefused('example-app|https://app.example.test/access|1,example-app|https://other.example.test/access|2', 'conflicting duplicate');
    }

    public function test_non_https_endpoints_are_refused_including_local_loopback(): void
    {
        foreach ([
            'http://app.example.test/access',
            'http://localhost/access',
            'http://127.0.0.1/access',
            'HTTPS://app.example.test/access',
            'ftp://app.example.test/access',
        ] as $endpoint) {
            $this->assertRefused("example-app|{$endpoint}|2", $endpoint);
        }
    }

    public function test_refusal_messages_never_echo_the_configured_value(): void
    {
        try {
            DelegatedAccessApplications::parse('example-app|https://user:synthetic-password@app.example.test/access|2');
            $this->fail('Expected credentials in the endpoint to be refused.');
        } catch (InvalidArgumentException $exception) {
            $this->assertStringContainsString('AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS entry 1', $exception->getMessage());
            $this->assertStringNotContainsString('synthetic-password', $exception->getMessage());
            $this->assertStringNotContainsString('app.example.test', $exception->getMessage());
        }
    }

    public function test_the_configuration_file_reads_the_environment_and_refuses_to_load_when_malformed(): void
    {
        $this->assertSame([], config('delegated-access.applications'));

        $this->withApplicationsEnvironment('example-app|https://app.example.test/application-access|2', function (): void {
            $configuration = require config_path('delegated-access.php');
            $this->assertSame(
                ['example-app' => ['endpoint' => 'https://app.example.test/application-access', 'contract_version' => 2]],
                $configuration['applications'],
            );
        });

        $this->withApplicationsEnvironment('example-app|http://app.example.test/application-access|2', function (): void {
            try {
                require config_path('delegated-access.php');
                $this->fail('Expected a malformed value to prevent configuration from loading.');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        });
    }

    private function assertRefused(mixed $value, string $label): void
    {
        try {
            DelegatedAccessApplications::parse($value);
            $this->fail("Expected the {$label} case to be refused.");
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
    }

    private function withApplicationsEnvironment(string $value, callable $callback): void
    {
        $key = DelegatedAccessApplications::ENVIRONMENT;
        $previous = [getenv($key), $_ENV[$key] ?? null, array_key_exists($key, $_ENV), $_SERVER[$key] ?? null, array_key_exists($key, $_SERVER)];
        putenv($key.'='.$value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;

        try {
            $callback();
        } finally {
            putenv($previous[0] === false ? $key : $key.'='.$previous[0]);
            if ($previous[2]) {
                $_ENV[$key] = $previous[1];
            } else {
                unset($_ENV[$key]);
            }
            if ($previous[4]) {
                $_SERVER[$key] = $previous[3];
            } else {
                unset($_SERVER[$key]);
            }
        }
    }
}
