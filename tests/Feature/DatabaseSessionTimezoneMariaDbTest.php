<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/** Real MariaDB: the session runs in UTC, so TIMESTAMP values are stored as the UTC instants the app writes. */
#[Group('mariadb')]
class DatabaseSessionTimezoneMariaDbTest extends TestCase
{
    public function test_session_time_zone_is_utc(): void
    {
        $this->assertSame('+00:00', DB::scalar('SELECT @@session.time_zone'));
        $this->assertSame(0, (int) DB::scalar('SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), NOW())'));
    }

    public function test_timestamp_columns_store_app_values_as_utc_instants(): void
    {
        Schema::create('session_timezone_probe', function ($table): void {
            $table->id();
            $table->timestamp('written_at')->nullable();
            $table->timestamp('defaulted_at')->useCurrent();
        });

        try {
            // 01:30 UTC on the spring-forward date: a wall time that does not exist in Europe/London.
            DB::table('session_timezone_probe')->insert(['written_at' => '2027-03-28 01:30:00']);
            $row = DB::table('session_timezone_probe')
                ->selectRaw('written_at, UNIX_TIMESTAMP(written_at) AS epoch, TIMESTAMPDIFF(SECOND, defaulted_at, UTC_TIMESTAMP()) AS default_lag')
                ->first();

            $this->assertNotNull($row);
            $this->assertSame('2027-03-28 01:30:00', $row->written_at);
            $this->assertSame(1806197400, (int) $row->epoch);
            $this->assertLessThan(60, abs((int) $row->default_lag));
        } finally {
            Schema::drop('session_timezone_probe');
        }
    }
}
