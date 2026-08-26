<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_client_grants', function (Blueprint $table): void {
            $table->foreignUuid('oauth_client_id')
                ->constrained('oauth_clients')
                ->cascadeOnDelete();
            $table->foreignId('subject')
                ->constrained('users')
                ->cascadeOnDelete();
            $table->timestamps();
            $table->primary(['oauth_client_id', 'subject']);
            $table->index('subject');
        });

        $subjects = DB::table('users')
            ->select(['id', 'user_role'])
            ->orderBy('id')
            ->get()
            ->filter(static function (object $user): bool {
                $roles = array_filter(array_map(
                    static fn (string $role): string => strtolower(trim($role)),
                    explode(',', (string) $user->user_role),
                ));

                return in_array('user', $roles, true) || in_array('admin', $roles, true);
            })
            ->map(static fn (object $user): int => (int) $user->id)
            ->all();

        $clientIds = DB::table('oauth_clients')
            ->where('revoked', false)
            ->orderBy('id')
            ->pluck('id')
            ->map(static fn (mixed $id): string => (string) $id)
            ->all();

        $now = now();
        $rows = [];

        foreach ($subjects as $subject) {
            foreach ($clientIds as $clientId) {
                $rows[] = [
                    'oauth_client_id' => $clientId,
                    'subject' => $subject,
                    'created_at' => $now,
                    'updated_at' => $now,
                ];

                if (count($rows) === 500) {
                    DB::table('oauth_client_grants')->insert($rows);
                    $rows = [];
                }
            }
        }

        if ($rows !== []) {
            DB::table('oauth_client_grants')->insert($rows);
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_client_grants');
    }
};
