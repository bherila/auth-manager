<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\DirectoryCopy\PrivateArchiveFile;
use Illuminate\Console\Command;

final class ExportDirectory extends Command
{
    protected $signature = 'identity:directory-export {--output= : New private file outside the web root; existing files are never overwritten}';

    protected $description = 'Export a checksummed portable provider directory without live tokens or sessions';

    public function handle(DirectoryTransfer $transfer): int
    {
        if (! is_string($this->option('output')) || $this->option('output') === '') {
            $this->error('Specify --output with a new private file. Directory material is never printed.');

            return self::INVALID;
        }
        try {
            PrivateArchiveFile::write($this->option('output'), DirectoryArchive::encode($transfer->snapshot()));
        } catch (\Throwable $failure) {
            // Database exceptions may include row values or secret hashes. Never print them.
            $this->error($failure instanceof \InvalidArgumentException ? $failure->getMessage() : 'Directory export failed. No usable archive was produced.');

            return self::FAILURE;
        }
        $this->info('Private directory archive created. It contains password and client-secret hashes; transfer only over a trusted private channel.');

        return self::SUCCESS;
    }
}
