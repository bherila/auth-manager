@extends('layouts.app')
@section('title', 'Confirm synthetic sign-in')
@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush
@section('content')
    <main class="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10">
        <section class="bg-card text-card-foreground border-border rounded-xl border p-6 shadow-sm"
            id="test-login-confirm" data-preview="{{ route('auth-manager.test-logins.preview') }}" data-confirm="{{ route('auth-manager.test-logins.confirm') }}">
            <h1 class="text-2xl font-semibold">Confirm synthetic sign-in</h1>
            <p class="text-muted-foreground mt-3" id="test-login-status" role="status">Checking this short-lived sign-in…</p>
            <p class="text-muted-foreground mt-3 text-sm">Continuing replaces your identity-provider session with this test account. Application permissions still apply.</p>
            <x-ui.button id="test-login-continue" type="button" class="mt-6 w-full" disabled>Continue as test account</x-ui.button>
            <noscript><p class="mt-3">JavaScript is required. Return to the application to start again.</p></noscript>
        </section>
    </main>
@endsection
@push('scripts')
    @vite(['resources/js/test-login-confirm.ts'])
@endpush
