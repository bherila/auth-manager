<?php

namespace BWH\AuthManager\Services\DirectoryCopy;

use InvalidArgumentException;

final class PrivateArchiveFile
{
    public static function write(string $path, string $bytes): void
    {
        $directory = realpath(dirname($path));
        if ($directory === false) {
            throw new InvalidArgumentException('The private archive directory does not exist.');
        }
        foreach ([base_path(), public_path()] as $unsafe) {
            $root = realpath($unsafe);
            if ($root !== false && ($directory === $root || str_starts_with($directory.'/', $root.'/'))) {
                throw new InvalidArgumentException('Write directory archives outside the application and web root.');
            }
        }
        if (strlen($bytes) > DirectoryArchive::MAX_BYTES) {
            throw new InvalidArgumentException('Directory archive exceeds the size limit.');
        }
        // Exclusive creation avoids overwriting another archive or following a symlink.
        $previous = umask(0077);
        try {
            $stream = @fopen($path, 'xb');
        } finally {
            umask($previous);
        }
        if ($stream === false) {
            throw new InvalidArgumentException('Cannot exclusively create the private archive file.');
        }
        try {
            if (! chmod($path, 0600) || fwrite($stream, $bytes) !== strlen($bytes) || ! fflush($stream)) {
                throw new InvalidArgumentException('Cannot finish writing the private archive file.');
            }
        } catch (\Throwable $failure) {
            fclose($stream);
            @unlink($path);
            throw $failure;
        }
        fclose($stream);
    }

    public static function read(string $path): string
    {
        $stat = @lstat($path);
        if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || ($stat['mode'] & 0077) !== 0) {
            throw new InvalidArgumentException('Import requires a regular private file with no group or other permissions.');
        }
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new InvalidArgumentException('Cannot read the private archive file.');
        }
        try {
            $opened = fstat($stream);
            if ($opened === false || $opened['ino'] !== $stat['ino'] || $opened['dev'] !== $stat['dev']) {
                throw new InvalidArgumentException('The private archive file changed while opening.');
            }
            $bytes = stream_get_contents($stream, DirectoryArchive::MAX_BYTES + 1);
            if ($bytes === false || strlen($bytes) > DirectoryArchive::MAX_BYTES) {
                throw new InvalidArgumentException('Cannot read a bounded directory archive.');
            }

            return $bytes;
        } finally {
            fclose($stream);
        }
    }
}
