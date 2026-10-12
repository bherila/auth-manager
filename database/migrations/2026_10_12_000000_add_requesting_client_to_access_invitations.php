<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The OAuth client an application requested an admission invitation through, or null for an
 * invitation sent from the provider's own pages. Such an invitation admits to that client alone.
 *
 * Nullable and unused by existing rows, so the previous release runs unchanged against it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->uuid('requesting_client_id')->nullable()->after('application');
            $table->index(['requesting_client_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->dropIndex(['requesting_client_id', 'created_at']);
            $table->dropColumn('requesting_client_id');
        });
    }
};
