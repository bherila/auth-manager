<?php

namespace Tests\Fixtures;

use App\Services\DelegatedAccess\DatabaseNonceStore;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

trait UsesDurableNonces
{
    private string $nonceDatabasePath;

    private function setUpNonceStore(): void
    {
        $this->nonceDatabasePath = tempnam(sys_get_temp_dir(), 'synthetic-nonces-');
        config(['database.connections.delegated_nonce_test' => [
            'driver' => 'sqlite', 'database' => $this->nonceDatabasePath, 'prefix' => '',
        ]]);
        DB::purge('delegated_nonce_test');
        Schema::connection('delegated_nonce_test')->create(DatabaseNonceStore::TABLE, function (Blueprint $table): void {
            $table->string('key', 64)->primary();
            $table->unsignedBigInteger('expires_at')->index();
        });
    }

    private function tearDownNonceStore(): void
    {
        DB::purge('delegated_nonce_test');
        @unlink($this->nonceDatabasePath);
    }

    private function nonceStore(): DatabaseNonceStore
    {
        return new DatabaseNonceStore(DB::connection('delegated_nonce_test'));
    }
}
