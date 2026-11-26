<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The subject this provider sends to relying applications becomes a column of its own instead
 * of the account's row id, so it can be carried across a restore or a copy and, later, be an
 * opaque value nobody can reissue by rolling back an auto-increment counter.
 *
 * Every existing account and tombstone keeps exactly the subject applications already bound:
 * the decimal string of its id. The columns stay nullable in this release because the previous
 * code may still be serving while this runs, and it inserts accounts and tombstones without
 * them. Readers fall back to the id for such a row (User::providerSubject(),
 * IdentityTombstone::providerSubject()). A later release backfills again and makes them NOT NULL.
 *
 * Subjects are case-sensitive, so MySQL and MariaDB compare them byte for byte rather than
 * through the table's case-insensitive default collation. Every stage is restartable: MySQL
 * commits DDL on its own.
 */
return new class extends Migration
{
    public function up(): void
    {
        $binary = in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true);

        if (! Schema::hasColumn('users', 'subject')) {
            Schema::table('users', function (Blueprint $table) use ($binary): void {
                $column = $table->string('subject', 64)->nullable()->after('id');
                if ($binary) {
                    $column->charset('ascii')->collation('ascii_bin');
                }
                $table->unique('subject', 'users_subject_unique');
            });
        }
        DB::table('users')->whereNull('subject')->update(['subject' => DB::raw('CAST(id AS CHAR)')]);

        if (! Schema::hasColumn('identity_tombstones', 'provider_subject')) {
            Schema::table('identity_tombstones', function (Blueprint $table) use ($binary): void {
                $column = $table->string('provider_subject', 64)->nullable()->after('subject');
                if ($binary) {
                    $column->charset('ascii')->collation('ascii_bin');
                }
                $table->unique('provider_subject', 'identity_tombstones_provider_subject_unique');
            });
        }
        DB::table('identity_tombstones')->whereNull('provider_subject')
            ->update(['provider_subject' => DB::raw('CAST(subject AS CHAR)')]);
    }

    public function down(): void
    {
        if (Schema::hasColumn('identity_tombstones', 'provider_subject')) {
            Schema::table('identity_tombstones', function (Blueprint $table): void {
                $table->dropUnique('identity_tombstones_provider_subject_unique');
                $table->dropColumn('provider_subject');
            });
        }
        if (Schema::hasColumn('users', 'subject')) {
            Schema::table('users', function (Blueprint $table): void {
                $table->dropUnique('users_subject_unique');
                $table->dropColumn('subject');
            });
        }
    }
};
