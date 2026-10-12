<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * One-time codes that prove the invited address before an application's own invitation creates an
 * account (see App\Services\Invitations\InvitationAddressVerification).
 *
 * A row per code sent, so a second send never replaces a code already in the person's inbox. Only a
 * keyed hash of each code is stored, bound to the invitation, its current link and its address; the
 * address itself appears only as a SHA-256 hash. Wrong entries and sends are counted on the
 * invitation, per link: a resend starts both again.
 *
 * New table and defaulted columns the previous release never reads, so it runs unchanged against them.
 *
 * MariaDB does not roll back DDL, and the first production run of this migration created the table
 * and then failed on an index name longer than 64 characters, leaving an empty table and no
 * migration record. A table that is still empty and has no columns added to access_invitations is
 * that leftover and is rebuilt; anything else stops the migration instead of guessing.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('invitation_acceptance_codes')) {
            $leftover = DB::table('invitation_acceptance_codes')->doesntExist()
                && ! Schema::hasColumn('access_invitations', 'verification_attempts');

            if (! $leftover) {
                throw new RuntimeException('invitation_acceptance_codes already exists with data or completed columns; refusing to rebuild it.');
            }

            Schema::drop('invitation_acceptance_codes');
        }

        Schema::create('invitation_acceptance_codes', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('access_invitation_id')->constrained('access_invitations')->cascadeOnDelete();
            $table->char('address_hash', 64);
            $table->char('code_hash', 64);
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamp('created_at')->nullable();

            // Explicit name: the generated one is 66 characters, over MariaDB's 64-character identifier limit.
            $table->index(['access_invitation_id', 'consumed_at'], 'invitation_codes_invitation_consumed_idx');
        });

        Schema::table('access_invitations', function (Blueprint $table): void {
            // Wrong codes entered since the live codes were last burned; at the limit they all are.
            $table->unsignedTinyInteger('verification_attempts')->default(0)->after('link_handed_over');
            // Codes delivered for the current link.
            $table->unsignedTinyInteger('verification_send_count')->default(0)->after('verification_attempts');
        });
    }

    public function down(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->dropColumn(['verification_attempts', 'verification_send_count']);
        });
        Schema::dropIfExists('invitation_acceptance_codes');
    }
};
