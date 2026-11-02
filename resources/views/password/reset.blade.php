@extends('layouts.app')

@section('title', 'Set a new password')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('content')
    <main class="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10 sm:px-6">
        <div class="bg-card text-card-foreground border-border rounded-xl border p-6 shadow-sm sm:p-8">
            <h1 class="text-2xl font-semibold tracking-tight">Set a new password</h1>

            <div class="mt-6">
                @if ($errors->any())
                    <div role="alert" class="border-destructive/40 bg-destructive/10 text-destructive mb-4 rounded-md border px-3 py-2 text-sm">
                        {{ $errors->first() }}
                    </div>
                @endif

                <form method="POST" action="{{ route('auth-manager.password.update') }}" class="space-y-4">
                    @csrf
                    <input type="hidden" name="token" value="{{ $token }}" />
                    <div class="space-y-2">
                        <x-ui.label for="email">Email</x-ui.label>
                        <x-ui.input
                            type="email"
                            id="email"
                            name="email"
                            :value="old('email', $email)"
                            required
                            autocomplete="username"
                            autocapitalize="none"
                            spellcheck="false"
                        />
                    </div>
                    <div class="space-y-2">
                        <x-ui.label for="password">New password</x-ui.label>
                        <x-ui.input
                            type="password"
                            id="password"
                            name="password"
                            required
                            minlength="{{ config('auth-manager.password_min_length') }}"
                            maxlength="255"
                            autocomplete="new-password"
                        />
                        <p class="text-muted-foreground text-sm">Use at least {{ config('auth-manager.password_min_length') }} characters.</p>
                    </div>
                    <div class="space-y-2">
                        <x-ui.label for="password_confirmation">Confirm new password</x-ui.label>
                        <x-ui.input
                            type="password"
                            id="password_confirmation"
                            name="password_confirmation"
                            required
                            minlength="{{ config('auth-manager.password_min_length') }}"
                            maxlength="255"
                            autocomplete="new-password"
                        />
                    </div>
                    <x-ui.button type="submit" size="lg" class="w-full">Reset password</x-ui.button>
                </form>
            </div>

            <a href="{{ route('auth-manager.login') }}" class="mt-4 inline-block text-sm underline">Back to sign in</a>
        </div>
    </main>
@endsection
