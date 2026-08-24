<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private string $uniqueIndex = 'passkey_credential_id_hash_unique';

    private string $regularIndex = 'passkey_credential_id_hash_index';

    public function up(): void
    {
        $tableName = config('bherila-auth.passkeys.table', 'auth_passkeys');

        if (! Schema::hasTable($tableName)) {
            return;
        }

        if (! Schema::hasColumn($tableName, 'credential_id_hash')) {
            Schema::table($tableName, function (Blueprint $table) {
                $table->string('credential_id_hash', 64)->nullable()->after('credential_id');
            });
        }

        DB::table($tableName)
            ->whereNull('credential_id_hash')
            ->whereNotNull('credential_id')
            ->orderBy('id')
            ->select(['id', 'credential_id'])
            ->chunkById(100, function ($credentials) use ($tableName): void {
                foreach ($credentials as $credential) {
                    DB::table($tableName)
                        ->where('id', $credential->id)
                        ->update(['credential_id_hash' => hash('sha256', $credential->credential_id)]);
                }
            });

        if (! $this->hasDuplicateHashes($tableName) && ! Schema::hasIndex($tableName, $this->uniqueIndex)) {
            Schema::table($tableName, function (Blueprint $table) {
                $table->unique('credential_id_hash', $this->uniqueIndex);
            });
        } elseif (! Schema::hasIndex($tableName, ['credential_id_hash'])) {
            Schema::table($tableName, function (Blueprint $table) {
                $table->index('credential_id_hash', $this->regularIndex);
            });
        }

        $this->dropWideCredentialIdUniqueIndex($tableName);
    }

    public function down(): void
    {
        $tableName = config('bherila-auth.passkeys.table', 'auth_passkeys');

        if (! Schema::hasTable($tableName) || ! Schema::hasColumn($tableName, 'credential_id_hash')) {
            return;
        }

        // Drop any index on credential_id_hash before the column, in a separate
        // schema operation. We resolve index names from getIndexes() rather than
        // assuming them: SQLite rebuilds the table on earlier column/index drops
        // and re-derives index names (so the custom name may no longer apply),
        // and dropping a column while an index still references it errors.
        $indexes = collect(Schema::getIndexes($tableName))
            ->filter(fn (array $index): bool => in_array('credential_id_hash', $index['columns'], true));

        Schema::table($tableName, function (Blueprint $table) use ($indexes) {
            foreach ($indexes as $index) {
                if ($index['unique']) {
                    $table->dropUnique($index['name']);
                } else {
                    $table->dropIndex($index['name']);
                }
            }
        });

        Schema::table($tableName, function (Blueprint $table) {
            $table->dropColumn('credential_id_hash');
        });
    }

    private function hasDuplicateHashes(string $tableName): bool
    {
        return DB::table($tableName)
            ->select('credential_id_hash')
            ->whereNotNull('credential_id_hash')
            ->groupBy('credential_id_hash')
            ->havingRaw('COUNT(*) > 1')
            ->limit(1)
            ->exists();
    }

    private function dropWideCredentialIdUniqueIndex(string $tableName): void
    {
        foreach (Schema::getIndexes($tableName) as $index) {
            if (! $index['unique'] || $index['columns'] !== ['credential_id']) {
                continue;
            }

            Schema::table($tableName, function (Blueprint $table) use ($index) {
                $table->dropUnique($index['name']);
            });
        }
    }
};
