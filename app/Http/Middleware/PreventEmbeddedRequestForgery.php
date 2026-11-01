<?php

namespace BWH\AuthManager\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;

/**
 * CSRF for the embedded provider, checked against the provider's own session.
 *
 * Sets no XSRF-TOKEN cookie: the host owns that name on the same origin, and the
 * provider's pages send the token from their csrf-token meta tag instead.
 */
final class PreventEmbeddedRequestForgery extends PreventRequestForgery
{
    protected $addHttpCookie = false;
}
