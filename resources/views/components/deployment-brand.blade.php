@php
    $branding = app(\BWH\AuthManager\Support\DeploymentBranding::class);
    $lightLogo = $branding->asset('logo_light');
    $darkLogo = $branding->asset('logo_dark') ?? $lightLogo;
    $nameInLogo = $branding->logoIncludesName();
    $logoAlt = $nameInLogo ? config('app.name') : '';
@endphp
<header class="provider-brand flex min-h-24 items-center justify-center gap-3 px-4 py-5">
    @if ($lightLogo)
        <img src="{{ $lightLogo }}" alt="{{ $logoAlt }}" class="max-h-12 max-w-48 object-contain dark:hidden" />
        <img src="{{ $darkLogo }}" alt="{{ $logoAlt }}" class="hidden max-h-12 max-w-48 object-contain dark:block" />
    @endif
    @unless ($nameInLogo)
        <span class="font-semibold">{{ config('app.name') }}</span>
    @endunless
</header>
