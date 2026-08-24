<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('bherila-auth.audit.table', 'auth_audit_log');

        if (Schema::hasTable($table)) {
            return;
        }

        $usersTable = $this->usersTable();

        Schema::create($table, function (Blueprint $blueprint) use ($usersTable) {
            $blueprint->id();
            $blueprint->foreignId('user_id')->nullable()->constrained($usersTable)->nullOnDelete();
            $blueprint->foreignId('acting_user_id')->nullable()->constrained($usersTable)->nullOnDelete();
            $blueprint->string('email')->nullable();
            $blueprint->string('event', 64);
            $blueprint->string('auth_method', 32)->nullable();
            $blueprint->boolean('succeeded');
            $blueprint->string('reason')->nullable();
            // varbinary(16) on MySQL, blob on SQLite — see BinaryIpAddressCast.
            $blueprint->binary('ip_address', 16)->nullable();
            $blueprint->text('user_agent')->nullable();
            $blueprint->string('session_id', 64)->nullable();
            $blueprint->boolean('is_suspicious')->default(false);
            $blueprint->json('metadata')->nullable();
            $blueprint->timestamps();

            $blueprint->index(['user_id', 'created_at']);
            $blueprint->index('event');
            $blueprint->index('email');
            $blueprint->index('created_at');
        });
    }

    public function down(): void
    {
        if (! config('bherila-auth.migrations.drop_tables_on_rollback', false)) {
            return;
        }

        Schema::dropIfExists(config('bherila-auth.audit.table', 'auth_audit_log'));
    }

    private function usersTable(): string
    {
        $model = config('bherila-auth.users.model');

        if (is_string($model) && class_exists($model)) {
            return (new $model)->getTable();
        }

        return 'users';
    }
};
