<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->softDeletes()->after('credential_version');
        });

        Schema::create('identity_tombstones', function (Blueprint $table): void {
            $table->id();
            $table->uuid('public_id')->unique();
            // Deliberately not a foreign key: the reconciliation record must outlive
            // the provider user row it describes.
            $table->unsignedBigInteger('subject')->unique();
            $table->timestamp('tombstoned_at');
            $table->timestamp('purge_after');
            $table->timestamp('provider_purged_at')->nullable();
            $table->string('purge_reason', 32)->nullable();
            $table->json('unacknowledged_clients')->nullable();
            $table->timestamps();

            $table->index(['provider_purged_at', 'purge_after']);
        });

        Schema::create('identity_tombstone_clients', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('identity_tombstone_id')
                ->constrained('identity_tombstones')
                ->cascadeOnDelete();
            // These are snapshots rather than foreign keys. Removing an OAuth client
            // must not erase evidence that it failed to acknowledge a deletion.
            $table->uuid('oauth_client_id');
            $table->string('oauth_client_name');
            $table->timestamp('acknowledged_at')->nullable();
            $table->timestamps();

            $table->unique(
                ['identity_tombstone_id', 'oauth_client_id'],
                'identity_tombstone_client_unique',
            );
            $table->index(
                ['oauth_client_id', 'acknowledged_at'],
                'identity_tombstone_client_pending_index',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('identity_tombstone_clients');
        Schema::dropIfExists('identity_tombstones');

        Schema::table('users', function (Blueprint $table): void {
            $table->dropSoftDeletes();
        });
    }
};
