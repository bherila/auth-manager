<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Services\OffboxAuditExport;
use BWH\AuthManager\Services\OffboxAuditExportRefused;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

/** The hourly off-box copy of the authentication audit log (docs/recovery.md). */
final class ExportAuditOffbox extends Command
{
    /** Unexported rows older than this mean the hourly export is not keeping up. */
    private const STALE_AFTER_MINUTES = 120;

    protected $signature = 'auth-manager:audit-export
        {--max-objects=100 : Most objects to write in one run; the next run continues}
        {--status : Report how far the export has got and whether it is current, writing nothing}';

    protected $description = 'Append new audit-log rows to the off-box export as immutable objects; never overwrites or deletes';

    public function handle(OffboxAuditExport $export): int
    {
        if ($this->option('status')) {
            return $this->status($export);
        }
        $maxObjects = filter_var($this->option('max-objects'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 10000]]);
        if ($maxObjects === false) {
            $this->error('--max-objects must be an integer from 1 to 10000.');

            return self::INVALID;
        }

        $lock = Cache::lock('auth-manager:audit-export', 3600);
        if (! $lock->get()) {
            $this->error('Another audit export is running. Nothing was exported.');

            return self::FAILURE;
        }
        try {
            $result = $export->export($maxObjects);
        } catch (OffboxAuditExportRefused $refused) {
            Log::error('The off-box audit export refused to run.', ['reason' => $refused->getMessage()]);
            $this->error($refused->getMessage());

            return self::FAILURE;
        } catch (Throwable $failure) {
            // Storage and database exceptions can carry row values or credentials. Never print them.
            Log::error('The off-box audit export failed.', ['exception' => $failure::class]);
            $this->error('The off-box audit export failed ('.$failure::class.'). Objects already written stay; the next run continues after the newest one.');

            return self::FAILURE;
        } finally {
            $lock->release();
        }

        if ($result['objects'] === []) {
            $this->info('No new audit rows to export.');
        } else {
            $this->info(sprintf('Exported %d audit rows in %d objects; the newest is %s.', $result['rows'], count($result['objects']), $result['objects'][array_key_last($result['objects'])]));
        }

        return self::SUCCESS;
    }

    private function status(OffboxAuditExport $export): int
    {
        try {
            $status = $export->status();
        } catch (OffboxAuditExportRefused $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        } catch (Throwable $failure) {
            $this->error('The off-box audit export could not be read ('.$failure::class.').');

            return self::FAILURE;
        }

        $this->line('Newest object: '.($status['newest'] ?? 'none'));
        $this->line('Exported through id: '.($status['last_id'] ?? 'none').($status['epoch'] !== null ? " (epoch {$status['epoch']})" : ''));
        $this->line('Database highest id: '.$status['database_max_id']);
        $this->line('Rows not yet exported: '.$status['pending'].($status['oldest_pending'] !== null ? ", the oldest from {$status['oldest_pending']}" : ''));

        if ($status['oldest_pending'] !== null
            && Carbon::parse($status['oldest_pending'])->lessThan(Carbon::now()->subMinutes(self::STALE_AFTER_MINUTES))) {
            $this->error(sprintf('The export is behind: a row older than %d minutes has not been exported.', self::STALE_AFTER_MINUTES));

            return self::FAILURE;
        }
        $this->info('The export is current.');

        return self::SUCCESS;
    }
}
