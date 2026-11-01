<?php

namespace BWH\AuthManager\Services\DelegatedAccess;

/** Monotonic time: wall-clock adjustments cannot extend a response deadline. */
class TransportClock
{
    public function now(): float
    {
        return hrtime(true) / 1_000_000_000;
    }
}
