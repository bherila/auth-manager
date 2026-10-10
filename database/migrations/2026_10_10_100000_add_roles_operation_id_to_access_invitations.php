<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The delegated access `operation_id` of an invitation's acceptance-time write (contract version 3).
 *
 * Chosen once, stored before the write is sent, and reused by any later attempt to apply the same
 * invitation, so the application answers a repeat from its receipt instead of applying it again.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->string('roles_operation_id', 64)->nullable()->after('roles_request_id');
        });
    }

    public function down(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->dropColumn('roles_operation_id');
        });
    }
};
