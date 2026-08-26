<?php

namespace App\Console\Commands;

use App\Services\IdentityTombstonePurger;
use Illuminate\Console\Command;

class PurgeIdentityTombstones extends Command
{
    protected $signature = 'identities:purge-tombstones';

    protected $description = 'Purge provider identities whose tombstones are fully acknowledged or past retention';

    public function handle(IdentityTombstonePurger $purger): int
    {
        $summary = $purger->purgeEligible();

        $this->components->info(sprintf(
            'Purged %d identities; %d remain within retention; %d expired with unacknowledged applications.',
            $summary['purged'] + $summary['expired_with_unacknowledged'],
            $summary['waiting'],
            $summary['expired_with_unacknowledged'],
        ));

        return self::SUCCESS;
    }
}
