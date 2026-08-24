@extends('layouts.app')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('content')
    <div class="mx-auto max-w-md px-4 py-12">
        <div class="bg-card text-card-foreground border-border rounded-lg border p-6 shadow-md">
            <h1 class="mb-2 text-2xl font-bold">Sign In</h1>
            <p class="text-muted-foreground mb-6 text-sm">
                Use a passkey or an emailed sign-in code — no password needed.
            </p>

            {{-- Passkey login (primary) --}}
            <div id="passkey-login-mount"></div>

            {{-- Passwordless email code (primary) --}}
            <div class="mt-6">
                <div class="relative mb-4">
                    <div class="absolute inset-0 flex items-center">
                        <div class="border-border w-full border-t"></div>
                    </div>
                    <div class="relative flex justify-center text-sm">
                        <span class="bg-card text-muted-foreground px-2">OR</span>
                    </div>
                </div>
                <div id="passwordless-login-mount"></div>
            </div>

            @if ($errors->has('email'))
                <p class="text-destructive mt-4 text-sm">{{ $errors->first('email') }}</p>
            @endif

            {{-- Password login (de-emphasized fallback) --}}
            <details class="group mt-6" {{ $errors->any() ? 'open' : '' }}>
                <summary class="text-muted-foreground hover:text-foreground cursor-pointer text-sm select-none">
                    Sign in with a password instead
                </summary>
                <form method="POST" action="/login" class="mt-4 space-y-4">
                    @csrf

                    <div>
                        <label for="email" class="text-foreground mb-1 block text-sm font-semibold">Email</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value="{{ old('email') }}"
                            required
                            class="bg-muted border-input text-foreground placeholder:text-muted-foreground focus:ring-ring focus:border-ring block w-full rounded-md border px-3 py-2 transition-colors focus:ring-2 focus:outline-none"
                        />
                    </div>

                    <div>
                        <label for="password" class="text-foreground mb-1 block text-sm font-semibold">Password</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            required
                            class="bg-muted border-input text-foreground placeholder:text-muted-foreground focus:ring-ring focus:border-ring block w-full rounded-md border px-3 py-2 transition-colors focus:ring-2 focus:outline-none"
                        />
                    </div>

                    <div class="flex items-center">
                        <input
                            type="checkbox"
                            id="remember"
                            name="remember"
                            class="border-input focus:ring-ring h-4 w-4 rounded text-blue-600"
                        />
                        <label for="remember" class="text-foreground ml-2 block text-sm">Keep me logged in</label>
                    </div>

                    <button
                        type="submit"
                        class="bg-muted text-foreground border-input hover:bg-muted/80 focus:ring-ring w-full cursor-pointer rounded-md border px-4 py-2 font-medium transition-colors focus:ring-2 focus:outline-none"
                    >
                        Sign In with Password
                    </button>
                </form>
            </details>

            {{-- Dev login section (local environment only) --}}
            @if (app()->environment('local'))
                <div class="mt-4">
                    <div class="relative mb-4">
                        <div class="absolute inset-0 flex items-center">
                            <div class="border-border w-full border-t"></div>
                        </div>
                        <div class="relative flex justify-center text-sm">
                            <span class="bg-card text-muted-foreground px-2">DEV</span>
                        </div>
                    </div>
                    <form method="POST" action="{{ route('login.dev.by-id') }}">
                        @csrf
                        <input type="hidden" name="user_id" value="1" />
                        <button
                            type="submit"
                            class="w-full cursor-pointer rounded-md bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-amber-700 focus:ring-2 focus:ring-amber-500 focus:outline-none"
                        >
                            Dev Login as UID=1
                        </button>
                    </form>
                </div>
            @endif
        </div>
    </div>
@endsection

@push('scripts')
    @vite(['resources/js/login-passkey.tsx'])
@endpush
