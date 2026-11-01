<?php

namespace BWH\AuthManager\Embedded\Console;

use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Support\Mount;
use Illuminate\Console\Command;

/**
 * The embedded provider's migrations, on its own connection and migrations table.
 *
 * Kept apart from the host's `migrate`: the provider's migration names (the Laravel
 * skeleton's users table among them) would collide in the host's repository, and its
 * tables need the prefixed connection.
 */
final class MigrateCommand extends Command
{
    protected $signature = 'auth-manager:migrate
        {--status : Show which provider migrations have run}
        {--force : Run in production}
        {--pretend : Show the SQL without running it}
        {--step : Record each migration as its own batch}';

    protected $description = "Run the embedded identity provider's migrations on its connection";

    public function handle(EmbeddedContext $context): int
    {
        // Entered here as well as on CommandStarting, which Laravel does not dispatch while
        // unit tests run; entries nest.
        return $context->run(fn (): int => $this->migrate());
    }

    private function migrate(): int
    {
        $published = database_path('migrations/auth-manager');
        $options = [
            '--database' => Mount::EMBEDDED_CONNECTION,
            '--path' => is_dir($published) ? $published : Mount::packagePath('database/migrations'),
            '--realpath' => true,
        ];

        if ($this->option('status')) {
            return $this->call('migrate:status', $options);
        }

        return $this->call('migrate', [
            ...$options,
            '--force' => (bool) $this->option('force'),
            '--pretend' => (bool) $this->option('pretend'),
            '--step' => (bool) $this->option('step'),
        ]);
    }
}
