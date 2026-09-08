<?php

namespace App\Services\DelegatedAccess;

interface NonceStore
{
    /** Atomically return true only on the first use; throw if storage is unavailable. */
    public function consume(string $key, int $seconds): bool;
}
