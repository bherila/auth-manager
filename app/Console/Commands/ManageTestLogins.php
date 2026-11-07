<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryCopy\PrivateArchiveFile;
use BWH\AuthManager\Services\TestLoginService;
use Illuminate\Console\Command;
use Illuminate\Validation\ValidationException;

final class ManageTestLogins extends Command
{
    protected $signature = 'auth-manager:test-logins
        {action : create, extend, disable, retire, or expire}
        {subject? : Existing flagged provider subject for extend, disable, or retire}
        {--name= : Synthetic display name for create}
        {--email= : Reserved or explicitly configured synthetic address for create}
        {--expires-at= : Explicit future UTC expiry, YYYY-MM-DDTHH:MM:SSZ}
        {--client=* : Static OAuth client ID to grant during create; repeatable and required}
        {--output= : New private credential JSON file outside application/web roots; create only}';

    protected $description = 'Provision and retire expiring synthetic password logins without printing credentials';

    public function handle(TestLoginService $logins): int
    {
        $action = (string) $this->argument('action');
        try {
            if (! in_array($action, ['create', 'extend', 'disable', 'retire', 'expire'], true)) {
                throw ValidationException::withMessages(['action' => 'Choose create, extend, disable, retire, or expire.']);
            }
            $this->assertOptions($action);
            if ($action === 'create') {
                $this->create($logins);
            } elseif ($action === 'expire') {
                $this->info('Disabled expired test logins: '.$logins->expire());
            } else {
                $subject = filter_var($this->argument('subject'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                if ($subject === false) {
                    throw ValidationException::withMessages(['subject' => 'Supply a positive flagged provider subject.']);
                }
                if ($action === 'extend') {
                    $logins->extend($subject, TestLoginService::parseExpiry((string) $this->option('expires-at')));
                } elseif ($action === 'disable') {
                    $logins->disable($subject);
                } else {
                    $logins->retire($subject);
                }
                $this->info('Test-login operation completed for subject '.$subject.'.');
            }
        } catch (\Throwable $failure) {
            if ($failure instanceof ValidationException) {
                foreach ($failure->errors() as $messages) {
                    foreach ($messages as $message) {
                        $this->error($message);
                    }
                }
            } else {
                // SQL/crypto exceptions can carry row values or credential material.
                $this->error($failure instanceof \InvalidArgumentException ? $failure->getMessage() : 'Test-login operation failed. Inspect private output before retrying creation.');
            }

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    private function create(TestLoginService $logins): void
    {
        $path = $this->option('output');
        if (! is_string($path) || $path === '') {
            throw ValidationException::withMessages(['output' => 'Specify a new private --output file; credentials are never printed.']);
        }
        // A lexical path under a web root could traverse a symlink to an
        // outside directory. Require its existing parent to be canonical too.
        if (dirname($path) !== realpath(dirname($path))) {
            throw ValidationException::withMessages(['output' => 'Use an absolute private output path with a canonical existing parent directory.']);
        }
        $expiry = TestLoginService::parseExpiry((string) $this->option('expires-at'));
        $clients = (array) $this->option('client');
        $user = $logins->create((string) $this->option('name'), (string) $this->option('email'), $expiry, $clients,
            static function (User $user, #[\SensitiveParameter] string $password) use ($path, $clients): void {
                // Reuse the directory export's exclusive, private, outside-web-root guards.
                PrivateArchiveFile::write($path, json_encode([
                    'contract_version' => 1, 'subject' => (string) $user->getKey(),
                    'email' => $user->email, 'password' => $password,
                    'expires_at' => $user->test_login_expires_at->utc()->format('Y-m-d\TH:i:s\Z'),
                    'oauth_client_ids' => $clients,
                ], JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT)."\n");
            });
        $this->info('Created test-login subject '.$user->getKey().'; credentials written once to a private file.');
    }

    private function assertOptions(string $action): void
    {
        if (in_array($action, ['create', 'expire'], true) && $this->argument('subject') !== null) {
            throw ValidationException::withMessages(['subject' => 'Create and expire do not take a subject.']);
        }
        foreach (['name', 'email', 'client', 'output'] as $option) {
            if ($action !== 'create' && ! in_array($this->option($option), [null, []], true)) {
                throw ValidationException::withMessages(['options' => 'Creation options are accepted only by create.']);
            }
        }
        if (! in_array($action, ['create', 'extend'], true) && $this->option('expires-at') !== null) {
            throw ValidationException::withMessages(['expires_at' => 'Only create and extend accept an expiry.']);
        }
    }
}
