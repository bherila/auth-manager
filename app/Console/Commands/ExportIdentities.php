<?php

namespace App\Console\Commands;

use App\Services\IdentityCopy\IdentityCopyDocument;
use App\Services\IdentityCopy\TableSequence;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Write selected identities to standard output for `identity:import` on another instance.
 *
 * The output contains password hashes. It is meant to be piped straight into the receiving
 * instance (`ssh source … identity:export … | ssh target … identity:import`) so it never lands
 * in a file, and the command refuses to print it to an interactive terminal. It reads only.
 */
class ExportIdentities extends Command
{
    protected $signature = 'identity:export
        {--subject=* : A subject (user id) to export; repeatable. Every one must exist and be active or disabled, never deleted.}
        {--allow-terminal : Print to an interactive terminal anyway. The output contains password hashes.}';

    protected $description = 'Export selected identities as JSON for identity:import on another instance.';

    public function handle(): int
    {
        $subjects = $this->subjects();
        if ($subjects === null) {
            return self::INVALID;
        }

        if (! $this->option('allow-terminal') && $this->stdoutIsTerminal()) {
            $this->errorLine('Refusing to print password hashes to a terminal. Pipe the output into identity:import.');

            return self::FAILURE;
        }

        $sequence = new TableSequence(DB::connection());
        if (! $sequence->supported()) {
            $this->errorLine('This database engine is not supported.');

            return self::FAILURE;
        }

        $rows = DB::table('users')
            ->whereIn('id', $subjects)
            ->orderBy('id')
            ->get([...IdentityCopyDocument::COLUMNS, 'deleted_at']);

        $missing = array_values(array_diff($subjects, $rows->pluck('id')->map(static fn (mixed $id): int => (int) $id)->all()));
        if ($missing !== []) {
            $this->errorLine('No such subject: '.implode(', ', $missing).'. Nothing was exported.');

            return self::FAILURE;
        }

        $deleted = $rows->whereNotNull('deleted_at')->pluck('id')->all();
        $tombstoned = DB::table('identity_tombstones')->whereIn('subject', $subjects)->pluck('subject')->all();
        $refused = array_values(array_unique(array_map('intval', [...$deleted, ...$tombstoned])));
        if ($refused !== []) {
            sort($refused);
            $this->errorLine('Deleted subjects cannot be copied: '.implode(', ', $refused).'. Nothing was exported.');

            return self::FAILURE;
        }

        // The receiving instance must never allocate an identifier this one has used: not for a
        // live person, a deleted one awaiting purge, or a tombstoned subject whose row is gone.
        $floor = max(
            $sequence->next('users'),
            (int) DB::table('users')->max('id') + 1,
            (int) DB::table('identity_tombstones')->max('subject') + 1,
        );

        $users = $rows->map(static function (object $row): array {
            $user = [];
            foreach (IdentityCopyDocument::COLUMNS as $column) {
                $user[$column] = $row->{$column};
            }
            $user['id'] = (int) $user['id'];

            return $user;
        })->all();

        $document = IdentityCopyDocument::make($floor, array_values($users));

        $this->output->writeln($document->encode(), OutputInterface::OUTPUT_RAW);
        $this->errorLine(sprintf('Exported %d identities; the receiving instance must allocate from %d.', count($users), $floor));

        return self::SUCCESS;
    }

    /**
     * @return list<int>|null
     */
    private function subjects(): ?array
    {
        $raw = (array) $this->option('subject');
        if ($raw === []) {
            $this->errorLine('Name at least one --subject.');

            return null;
        }

        $subjects = [];
        foreach ($raw as $value) {
            if (! is_string($value) || preg_match('/^[1-9][0-9]{0,18}$/D', $value) !== 1) {
                $this->errorLine('A subject must be a positive integer.');

                return null;
            }
            $subjects[(int) $value] = (int) $value;
        }
        ksort($subjects);

        return array_values($subjects);
    }

    private function stdoutIsTerminal(): bool
    {
        return function_exists('stream_isatty') && defined('STDOUT') && @stream_isatty(STDOUT)
            && $this->output->getOutput() instanceof ConsoleOutputInterface;
    }

    /**
     * Diagnostics go to standard error so standard output stays a clean document.
     */
    private function errorLine(string $message): void
    {
        $output = $this->output->getOutput();
        $target = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $target->writeln($message);
    }
}
