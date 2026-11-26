<?php

namespace BWH\AuthManager\Services\DirectoryCopy;

use InvalidArgumentException;

/** Private, checksummed transport. The checksum detects corruption, not an untrusted sender. */
final class DirectoryArchive
{
    public const FORMAT = 'auth-manager.directory-copy';

    /** 2: access groups and the direct-grant flag. 3: `users.subject` and `identity_tombstones.provider_subject`. */
    public const VERSION = 3;

    /** Versions still read. A version 2 archive's subjects were its account ids. */
    public const READABLE = [2, 3];

    public const MAX_BYTES = 67108864;

    /** @param array<string, mixed> $payload */
    public static function encode(array $payload): string
    {
        $bytes = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return json_encode([
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'sha256' => hash('sha256', $bytes),
            'payload' => base64_encode($bytes),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)."\n";
    }

    /** @return array{checksum: string, payload: array<string, mixed>} */
    public static function decode(string $bytes): array
    {
        if (strlen($bytes) > self::MAX_BYTES) {
            throw new InvalidArgumentException('Directory archive exceeds the size limit.');
        }
        try {
            $envelope = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
            if (! is_array($envelope) || array_keys($envelope) !== ['format', 'version', 'sha256', 'payload']
                || $envelope['format'] !== self::FORMAT || ! in_array($envelope['version'], self::READABLE, true)
                || ! is_string($envelope['payload']) || ! is_string($envelope['sha256'])) {
                throw new InvalidArgumentException('Unsupported directory archive format.');
            }
            $payloadBytes = base64_decode($envelope['payload'], true);
            if ($payloadBytes === false || ! hash_equals(hash('sha256', $payloadBytes), $envelope['sha256'])) {
                throw new InvalidArgumentException('Directory archive checksum does not match.');
            }
            $payload = json_decode($payloadBytes, true, 64, JSON_THROW_ON_ERROR);
            if (! is_array($payload)) {
                throw new InvalidArgumentException('Directory archive payload is invalid.');
            }
        } catch (\JsonException) {
            throw new InvalidArgumentException('Directory archive is not valid JSON.');
        }

        return ['checksum' => $envelope['sha256'], 'payload' => $envelope['version'] === 2 ? self::fromVersion2($payload) : $payload];
    }

    /**
     * Version 2 predates subjects as a column: every account's subject was its id, and every
     * tombstone's its numeric subject. Add both in their version 3 positions, still packed, and
     * leave anything malformed for the import's validation to refuse.
     *
     * @param  array<mixed>  $payload
     * @return array<mixed>
     */
    private static function fromVersion2(array $payload): array
    {
        $upgrade = static function (mixed $rows, string $after, string $column, string $from): mixed {
            if (! is_array($rows)) {
                return $rows;
            }

            return array_map(static function (mixed $row) use ($after, $column, $from): mixed {
                if (! is_array($row) || ! array_key_exists($after, $row) || ! array_key_exists($from, $row) || array_key_exists($column, $row)) {
                    return $row;
                }
                $upgraded = [];
                foreach ($row as $key => $value) {
                    $upgraded[$key] = $value;
                    if ($key === $after) {
                        $upgraded[$column] = $row[$from];
                    }
                }

                return $upgraded;
            }, $rows);
        };
        if (isset($payload['tables']) && is_array($payload['tables'])) {
            if (array_key_exists('users', $payload['tables'])) {
                $payload['tables']['users'] = $upgrade($payload['tables']['users'], 'id', 'subject', 'id');
            }
            if (array_key_exists('identity_tombstones', $payload['tables'])) {
                $payload['tables']['identity_tombstones'] = $upgrade($payload['tables']['identity_tombstones'], 'subject', 'provider_subject', 'subject');
            }
        }

        return $payload;
    }

    /** @param array<string, mixed> $row @return array<string, string|null> */
    public static function packRow(array $row): array
    {
        // Binary credential data must survive JSON exactly, including non-UTF-8 bytes.
        return array_map(static fn (mixed $value): ?string => $value === null ? null : base64_encode((string) $value), $row);
    }

    /** @param array<string, mixed> $row @return array<string, string|null> */
    public static function unpackRow(array $row): array
    {
        return array_map(static function (mixed $value): ?string {
            if ($value === null) {
                return null;
            }
            if (! is_string($value) || ($decoded = base64_decode($value, true)) === false) {
                throw new InvalidArgumentException('Directory archive contains an invalid encoded value.');
            }

            return $decoded;
        }, $row);
    }
}
