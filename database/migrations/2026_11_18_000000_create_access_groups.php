<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Access groups grant applications to their members. A group's grants are expanded into the
 * same `oauth_client_grants` rows sign-in already checks; `direct` records whether a row also
 * stands on its own, so removing a person from a group never removes access granted directly.
 * Every existing grant was made directly.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_client_grants', function (Blueprint $table): void {
            $table->boolean('direct')->default(true)->after('subject');
        });

        Schema::create('access_groups', function (Blueprint $table): void {
            $table->id();
            $table->string('name', 100)->unique();
            $table->string('description', 500)->nullable();
            $table->timestamps();
        });

        Schema::create('access_group_members', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('access_group_id')->constrained('access_groups')->cascadeOnDelete();
            $table->foreignId('subject')->constrained('users')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['access_group_id', 'subject'], 'access_group_members_unique');
            $table->index('subject', 'access_group_members_subject');
        });

        Schema::create('access_group_clients', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('access_group_id')->constrained('access_groups')->cascadeOnDelete();
            $table->foreignUuid('oauth_client_id')->constrained('oauth_clients')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['access_group_id', 'oauth_client_id'], 'access_group_clients_unique');
            $table->index('oauth_client_id', 'access_group_clients_client');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('access_group_clients');
        Schema::dropIfExists('access_group_members');
        Schema::dropIfExists('access_groups');
        Schema::table('oauth_client_grants', function (Blueprint $table): void {
            $table->dropColumn('direct');
        });
    }
};
