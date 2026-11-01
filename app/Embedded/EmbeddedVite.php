<?php

namespace BWH\AuthManager\Embedded;

use BWH\AuthManager\Support\Mount;
use Illuminate\Foundation\Vite;

/**
 * `@vite` for the embedded provider's pages: the package's own manifest and hot file,
 * with URLs below the prefix that EmbeddedAssetController (or published copies) serve.
 * The host's Vite instance, manifest and dev server are never consulted.
 */
final class EmbeddedVite extends Vite
{
    public static function create(): self
    {
        return (new self)
            ->useBuildDirectory(Mount::prefix().'/build')
            ->useHotFile(Mount::packagePath('public/hot'));
    }

    protected function manifestPath($buildDirectory)
    {
        return Mount::packagePath('public/build/'.$this->manifestFilename);
    }
}
