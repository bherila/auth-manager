<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Support\Mount;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** The first middleware of every embedded route: see EmbeddedContext. */
final class EnterEmbeddedContext
{
    public function __construct(private readonly EmbeddedContext $context) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! Mount::embedded()) {
            return $next($request);
        }

        return $this->context->run(static fn (): Response => $next($request));
    }
}
