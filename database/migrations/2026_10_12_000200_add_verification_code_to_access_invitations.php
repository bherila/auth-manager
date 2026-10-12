<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The one-time code that proves the invited address before an application's own invitation creates
 * an account (see App\Services\Invitations\InvitationAddressVerification). Only a keyed hash of the
 * code is stored, bound to the invitation, its current link and its address.
 *
 * Nullable or defaulted and unused by the previous release, so it runs unchanged against it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->char('verification_code_hash', 64)->nullable()->after('link_handed_over');
            $table->timestamp('verification_expires_at')->nullable()->after('verification_code_hash');
            // Wrong codes entered against the current code; it is spent at the limit.
            $table->unsignedTinyInteger('verification_attempts')->default(0)->after('verification_expires_at');
            // Codes sent for the current link; a resend (a new link) starts again.
            $table->unsignedTinyInteger('verification_send_count')->default(0)->after('verification_attempts');
        });
    }

    public function down(): void
    {
        Schema::table('access_invitations', function (Blueprint $table): void {
            $table->dropColumn(['verification_code_hash', 'verification_expires_at', 'verification_attempts', 'verification_send_count']);
        });
    }
};
