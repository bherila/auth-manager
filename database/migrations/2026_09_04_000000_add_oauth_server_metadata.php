<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /** Add only absent columns so this remains safe beside package publication. */
    public function up(): void
    {
        $this->addColumn('oauth_clients', 'dynamically_registered_at', function (Blueprint $table): void {
            $table->timestamp('dynamically_registered_at')->nullable();
        });
        $this->addColumn('oauth_clients', 'last_used_at', function (Blueprint $table): void {
            $table->timestamp('last_used_at')->nullable();
        });
        $this->addColumn('oauth_clients', 'scopes', function (Blueprint $table): void {
            $table->json('scopes')->nullable();
        });
        $this->addColumn('oauth_auth_codes', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
        $this->addColumn('oauth_access_tokens', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
        $this->addColumn('oauth_refresh_tokens', 'resource_uri', function (Blueprint $table): void {
            $table->text('resource_uri')->nullable();
        });
    }

    /** A no-op: skipped pre-existing columns are not safe to later remove. */
    public function down(): void {}

    /** @param callable(Blueprint): void $definition */
    private function addColumn(string $tableName, string $column, callable $definition): void
    {
        $schema = $this->schema();

        if (! $schema->hasTable($tableName) || $schema->hasColumn($tableName, $column)) {
            return;
        }

        $schema->table($tableName, $definition);
    }

    /** Keep metadata beside Passport's OAuth tables when it uses a separate database. */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    private function schema(): Builder
    {
        return Schema::connection($this->getConnection());
    }
};
