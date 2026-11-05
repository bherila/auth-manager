<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\DirectoryCopy\PrivateArchiveFile;
use Illuminate\Console\Command;

final class ImportDirectory extends Command
{
    protected $signature = 'identity:directory-import
        {--input= : Private directory archive file}
        {--apply : Apply to a fresh directory; otherwise report the plan without writing}
        {--skip-incompatible-passkeys : Explicitly omit passkeys whose original RP ID is incompatible}';

    protected $description = 'Import a portable provider directory with original subjects; dry run by default';

    public function handle(DirectoryTransfer $transfer): int
    {
        if (! is_string($this->option('input')) || $this->option('input') === '') {
            $this->error('Specify --input with a private directory archive file.');

            return self::INVALID;
        }
        try {
            $archive = DirectoryArchive::decode(PrivateArchiveFile::read($this->option('input')));
            $report = $transfer->import($archive['checksum'], $archive['payload'], (bool) $this->option('apply'), (bool) $this->option('skip-incompatible-passkeys'));
        } catch (\Throwable $failure) {
            $this->error($failure instanceof \InvalidArgumentException ? $failure->getMessage() : 'Directory import failed. Row changes were rolled back; allocation floors may already have increased.');

            return self::FAILURE;
        }
        $this->line($this->option('apply') ? 'Apply complete (an existing receipt means no changes).' : 'Dry run: no changes.');
        foreach ($report as $key => $count) {
            $this->line($key.': '.$count);
        }
        $this->warn('Live tokens, sessions, trusted devices and verification codes are not copied. Configure the target issuer, RP ID, signing keys and integration keys independently. Resend pending invitations on the new host; old verification codes do not survive.');

        return self::SUCCESS;
    }
}
