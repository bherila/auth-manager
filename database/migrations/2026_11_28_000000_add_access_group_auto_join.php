<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Default access (docs/default-access.md). A group marked `auto_join` takes in every account
 * created from then on. `access_group_opt_outs` records that an administrator took a person out
 * of such a group, so a later backfill never puts them back. Additive: the previous release
 * ignores both, and every existing group starts as an ordinary one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('access_groups', function (Blueprint $table): void {
            $table->boolean('auto_join')->default(false)->after('description');
        });

        Schema::create('access_group_opt_outs', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('access_group_id')->constrained('access_groups')->cascadeOnDelete();
            $table->foreignId('subject')->constrained('users')->cascadeOnDelete();
            $table->timestamps();
            $table->unique(['access_group_id', 'subject'], 'access_group_opt_outs_unique');
            $table->index('subject', 'access_group_opt_outs_subject');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('access_group_opt_outs');
        Schema::table('access_groups', function (Blueprint $table): void {
            $table->dropColumn('auto_join');
        });
    }
};
