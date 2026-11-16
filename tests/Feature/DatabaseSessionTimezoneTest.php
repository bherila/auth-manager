<?php

namespace Tests\Feature;

use Tests\TestCase;

/**
 * MariaDB converts TIMESTAMP columns and CURRENT_TIMESTAMP through the session time zone,
 * which defaults to the host's SYSTEM zone. The app writes UTC, so the app's MySQL-family
 * connections must pin their session to UTC or stored instants drift an hour during DST.
 */
class DatabaseSessionTimezoneTest extends TestCase
{
    public function test_application_timezone_is_utc(): void
    {
        $this->assertSame('UTC', config('app.timezone'));
    }

    public function test_app_mysql_family_connections_pin_their_session_to_utc(): void
    {
        foreach (['mysql', 'mariadb'] as $name) {
            $this->assertSame('+00:00', config("database.connections.{$name}.timezone"), sprintf(
                "config/database.php connection `%s` must set 'timezone' => '+00:00'; without it MariaDB uses the host's SYSTEM zone.",
                $name,
            ));
        }
    }

    /** The legacy import reads rows as their writers stored them, so it keeps the server zone. */
    public function test_legacy_identity_source_keeps_the_server_session_zone(): void
    {
        $this->assertNull(config('database.connections.legacy_identity.timezone'));
    }
}
