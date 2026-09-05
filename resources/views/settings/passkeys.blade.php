@extends('layouts.app')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('title', 'Manage passkeys')

@section('content')
    <main class="mx-auto max-w-2xl px-4 py-10">
        <a href="{{ url('/') }}" class="text-muted-foreground text-sm underline hover:text-foreground">Back to account</a>

        <header class="mt-6 mb-6">
            <h1 class="text-2xl font-semibold tracking-tight">Manage passkeys</h1>
            <p class="text-muted-foreground mt-2 text-sm">
                Add or remove passkeys used to sign in to this identity provider. Passkeys must be registered separately for each relying-party domain.
            </p>
            <p class="text-muted-foreground mt-2 text-sm">
                For your security, add or remove a passkey within ten minutes of signing in.
            </p>
            <a href="{{ route('login') }}" class="text-accent-foreground mt-3 inline-block text-sm underline">Sign in again</a>
        </header>

        <div id="passkey-management-mount">
            <div class="bg-card border-border h-64 animate-pulse rounded-xl border" aria-hidden="true"></div>
        </div>
    </main>
@endsection

@push('scripts')
    @vite(['resources/js/passkey-management.tsx'])
@endpush
