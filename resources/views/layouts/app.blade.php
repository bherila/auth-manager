<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    @php
        $branding = app(\App\Support\DeploymentBranding::class);
        $pageTitle = trim($__env->yieldContent('title', config('app.name')));
    @endphp
    <title>{{ $pageTitle }}{{ $branding->enabled() && $pageTitle !== config('app.name') ? ' — '.config('app.name') : '' }}</title>
    @include('layouts.theme-init')
    @stack('head')
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    @if ($favicon = $branding->asset('favicon'))
        <link rel="icon" href="{{ $favicon }}" />
    @endif
    @if ($stylesheet = $branding->asset('stylesheet'))
        <link rel="stylesheet" href="{{ $stylesheet }}" />
    @endif
</head>
<body class="bg-background text-foreground min-h-screen antialiased {{ $branding->enabled() ? 'provider-branded' : '' }}">
    @if ($branding->enabled())
        <x-deployment-brand />
    @endif
    @yield('content')
    @stack('scripts')
</body>
</html>
