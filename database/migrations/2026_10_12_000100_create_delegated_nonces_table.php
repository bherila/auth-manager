<?php

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Assertion ids already used, so an application's signed actor assertion is accepted once.
 *
 * The auth package's dedicated nonce table, as its DatabaseNonceStore expects it: outside every
 * business transaction and never cleared with the cache. Created on the connection the endpoint
 * uses (`application-invitations.nonce_connection`, the default when unset). Expired rows are
 * pruned by the scheduler.
 */
return new class extends Migration
{
    public function up(): void
    {
        $schema = Schema::connection(config('application-invitations.nonce_connection'));
        if ($schema->hasTable(DatabaseNonceStore::TABLE)) {
            return;
        }
        $schema->create(DatabaseNonceStore::TABLE, function (Blueprint $table): void {
            $table->string('key', 64)->primary();
            $table->unsignedBigInteger('expires_at')->index();
        });
    }

    public function down(): void
    {
        Schema::connection(config('application-invitations.nonce_connection'))->dropIfExists(DatabaseNonceStore::TABLE);
    }
};
