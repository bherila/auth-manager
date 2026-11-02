@extends('layouts.app')

@section('title', 'Sign in')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

{{-- DOM contract shared with resources/js/auth/login-dom.ts. The React islands
     enhance this server-rendered page and only ever touch the ids below:

       password-login       wrapper hidden while the emailed-code step is shown
       password-login-form  native POST /login form; submitting aborts passkey autofill
       email / password / remember   the inputs every sign-in method reads
       password-toggle      show/hide password button, hidden until JS runs
       forgot-password      "Forgot password?" button, hidden until JS runs. Replaced by a plain
                            link to the reset page on an instance that allows self-service reset
       login-error          server-side error block referenced by aria-describedby
       passkey-login-mount / email-code-login-mount   React roots

     After a password is accepted on an instance that requires a code, this page
     shows only the code step: email-code-login-mount carries data-attempt-token and
     data-email, and <noscript> offers the same step as a plain form.

     During a re-authentication that names methods, only those are rendered, so any of
     these ids can be absent.

     The password form must keep working with JavaScript disabled. --}}

@section('content')
    <main class="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10 sm:px-6">
        @unless (app(\BWH\AuthManager\Support\DeploymentBranding::class)->enabled())
            <p class="text-muted-foreground mb-3 text-center text-sm font-medium">{{ config('app.name') }}</p>
        @endunless

        <div class="bg-card text-card-foreground border-border rounded-xl border p-6 shadow-sm sm:p-8">
            <h1 class="text-2xl font-semibold tracking-tight">Sign in</h1>

            @if ($reauthenticating ?? false)
                <p class="text-muted-foreground mt-2 text-sm">Sign in again to continue.</p>
            @endif

            @isset($passwordChallenge)
                <div
                    id="email-code-login-mount"
                    class="mt-6"
                    data-attempt-token="{{ $passwordChallenge['attempt_token'] }}"
                    data-email="{{ $passwordChallenge['email'] }}"
                ></div>

                <noscript>
                    <div class="mt-6 space-y-4">
                        <p class="text-muted-foreground text-sm">
                            We sent {{ $passwordChallenge['email'] }} a 6-digit code. It expires in 15 minutes.
                        </p>
                        @error('code')
                            <div role="alert" class="border-destructive/40 bg-destructive/10 text-destructive rounded-md border px-3 py-2 text-sm">
                                {{ $message }}
                            </div>
                        @enderror
                        <form method="POST" action="{{ \BWH\AuthManager\Support\Mount::path('/api/auth/two-factor/verify') }}" class="space-y-4">
                            @csrf
                            <input type="hidden" name="attempt_token" value="{{ $passwordChallenge['attempt_token'] }}" />
                            <div class="space-y-2">
                                <x-ui.label for="noscript-code">Verification code</x-ui.label>
                                <x-ui.input
                                    id="noscript-code"
                                    name="code"
                                    inputmode="numeric"
                                    pattern="[0-9]{6}"
                                    maxlength="6"
                                    autocomplete="one-time-code"
                                    required
                                />
                            </div>
                            <x-ui.button type="submit" size="lg" class="w-full">Verify and sign in</x-ui.button>
                        </form>
                        <form method="POST" action="{{ route('auth-manager.login.challenge.cancel') }}">
                            @csrf
                            <x-ui.button type="submit" variant="link">Start over</x-ui.button>
                        </form>
                    </div>
                </noscript>
            @else
            <p class="text-muted-foreground mt-1 text-sm">Use a passkey, or your email and password.</p>

            {{-- Passkey (React island). The placeholder matches the mounted button's
                 height so the card does not jump when the bundle hydrates. --}}
            @php
                $offers = static fn (string $method): bool => ($offeredMethods ?? null) === null || in_array($method, $offeredMethods, true);
            @endphp

            @if ($offers('passkey'))
            <div id="passkey-login-mount" class="mt-6">
                <div class="bg-muted h-10 w-full rounded-md motion-safe:animate-pulse" aria-hidden="true"></div>
            </div>
            @endif

            @if ($offers('passkey') && ($offers('password') || $offers('code')))
            <div class="my-6 flex items-center gap-3" aria-hidden="true">
                <hr class="border-border flex-1" />
                <span class="text-muted-foreground text-xs font-medium tracking-wide uppercase">or</span>
                <hr class="border-border flex-1" />
            </div>
            @endif

            @php
                $hasError = $errors->has('email');
                $emailPrefilled = old('email', '') !== '';
            @endphp

            @if ($offers('password') || $offers('code'))
            <div id="password-login" @class(["mt-6" => ! $offers("passkey")])>
                @if (session('status'))
                    <div role="status" class="border-border bg-muted mb-4 rounded-md border px-3 py-2 text-sm">
                        {{ session('status') }}
                    </div>
                @endif

                @if ($hasError)
                    <div
                        id="login-error"
                        role="alert"
                        class="border-destructive/40 bg-destructive/10 text-destructive mb-4 rounded-md border px-3 py-2 text-sm"
                    >
                        {{ $errors->first('email') }}
                    </div>
                @endif

                <form id="password-login-form" method="POST" action="{{ route('auth-manager.login') }}" class="space-y-4">
                    @csrf

                    <div class="space-y-2">
                        <x-ui.label for="email">Email</x-ui.label>
                        <x-ui.input
                            type="email"
                            id="email"
                            name="email"
                            :value="old('email')"
                            required
                            autocomplete="username webauthn"
                            inputmode="email"
                            autocapitalize="none"
                            spellcheck="false"
                            :autofocus="! $emailPrefilled"
                            :aria-invalid="$hasError ? 'true' : null"
                            :aria-describedby="$hasError ? 'login-error' : null"
                        />
                    </div>

                    @if ($offers('password'))
                    <div class="space-y-2">
                        <div class="flex items-center justify-between gap-2">
                            <x-ui.label for="password">Password</x-ui.label>
                            @if (config('auth-manager.sign_in.password_reset'))
                                <a href="{{ route('auth-manager.password.request') }}" class="text-sm underline">Forgot password?</a>
                            @else
                                <x-ui.button id="forgot-password" variant="link" size="sm" class="h-auto px-0" hidden>
                                    Forgot password?
                                </x-ui.button>
                            @endif
                        </div>
                        <div class="relative">
                            <x-ui.input
                                type="password"
                                id="password"
                                name="password"
                                required
                                autocomplete="current-password"
                                class="pr-16"
                                :autofocus="$emailPrefilled"
                                :aria-invalid="$hasError ? 'true' : null"
                                :aria-describedby="$hasError ? 'login-error' : null"
                            />
                            <x-ui.button
                                id="password-toggle"
                                variant="ghost"
                                size="sm"
                                class="absolute inset-y-0 right-1 my-auto h-7 px-2 text-xs"
                                aria-controls="password"
                                aria-pressed="false"
                                aria-label="Show password"
                                hidden
                            >
                                Show
                            </x-ui.button>
                        </div>
                    </div>

                    <label for="remember" class="flex min-h-6 cursor-pointer items-center gap-2 text-sm">
                        <input
                            type="checkbox"
                            id="remember"
                            name="remember"
                            value="1"
                            @checked(old('remember'))
                            class="border-input accent-primary size-4 rounded"
                        />
                        Keep me signed in
                    </label>

                    <x-ui.button type="submit" size="lg" class="w-full">Sign in</x-ui.button>
                    @endif
                </form>
            </div>
            @endif

            {{-- Emailed sign-in code (React island). Mounted outside #password-login so it
                 stays visible while that section is hidden during the code step. --}}
            @if (config('auth-manager.sign_in.code_only') && $offers('code'))
                <div id="email-code-login-mount" class="mt-3">
                    <div class="bg-muted h-10 w-full rounded-md motion-safe:animate-pulse" aria-hidden="true"></div>
                </div>
            @endif
            @endisset

            @if (app()->environment('local'))
                <section aria-labelledby="dev-login-heading" class="border-border mt-6 border-t pt-4">
                    <h2 id="dev-login-heading" class="text-muted-foreground text-xs font-semibold tracking-wide uppercase">
                        Development only
                    </h2>
                    <form method="POST" action="{{ route('auth-manager.login.dev.by-id') }}" class="mt-2">
                        @csrf
                        <input type="hidden" name="user_id" value="1" />
                        <x-ui.button type="submit" variant="secondary" class="w-full">Sign in as user #1 (dev)</x-ui.button>
                    </form>
                </section>
            @endif
        </div>
    </main>
@endsection

@push('scripts')
    @vite(['resources/js/login.tsx'])
@endpush
