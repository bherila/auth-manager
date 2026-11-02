@extends('layouts.app')

@section('title', 'Reset your password')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('content')
    <main class="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10 sm:px-6">
        <div class="bg-card text-card-foreground border-border rounded-xl border p-6 shadow-sm sm:p-8">
            <h1 class="text-2xl font-semibold tracking-tight">Reset your password</h1>
            <p class="text-muted-foreground mt-2 text-sm">Enter your account email, and we'll send you a link to set a new password.</p>

            <div class="mt-6">
                @if (session('status'))
                    <div role="status" class="border-border bg-muted mb-4 rounded-md border px-3 py-2 text-sm">
                        {{ session('status') }}
                    </div>
                @endif

                @error('email')
                    <div role="alert" class="border-destructive/40 bg-destructive/10 text-destructive mb-4 rounded-md border px-3 py-2 text-sm">
                        {{ $message }}
                    </div>
                @enderror

                <form method="POST" action="{{ route('auth-manager.password.email') }}" class="space-y-4">
                    @csrf
                    <div class="space-y-2">
                        <x-ui.label for="email">Email</x-ui.label>
                        <x-ui.input
                            type="email"
                            id="email"
                            name="email"
                            :value="old('email')"
                            required
                            autocomplete="username"
                            autocapitalize="none"
                            spellcheck="false"
                            autofocus
                        />
                    </div>
                    <x-ui.button type="submit" size="lg" class="w-full">Send reset link</x-ui.button>
                </form>
            </div>

            <a href="{{ route('auth-manager.login') }}" class="mt-4 inline-block text-sm underline">Back to sign in</a>
        </div>
    </main>
@endsection
