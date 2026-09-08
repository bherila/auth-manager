@extends('layouts.app')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('title', 'Account and security')

@section('content')
    <main class="mx-auto max-w-2xl space-y-8 px-4 py-10">
        <a href="{{ url('/') }}" class="text-muted-foreground text-sm underline">Back to home</a>
        <header>
            <h1 class="text-2xl font-semibold tracking-tight">Account and security</h1>
            <p class="text-muted-foreground mt-2">Manage how you sign in to this identity provider.</p>
        </header>
        <section aria-labelledby="profile-heading" class="rounded-xl border border-border bg-card p-6">
            <h2 id="profile-heading" class="text-lg font-semibold">Your profile</h2>
            <dl class="mt-4 space-y-2"><dt class="text-muted-foreground text-sm">Name</dt><dd>{{ $person->name }}</dd><dt class="text-muted-foreground text-sm">Email</dt><dd>{{ $person->email }}</dd></dl>
            <p class="text-muted-foreground mt-4 text-sm">Contact an administrator to change your name or email. Application preferences and report settings stay in each application.</p>
        </section>
        <section aria-labelledby="password-heading" class="rounded-xl border border-border bg-card p-6">
            <h2 id="password-heading" class="text-lg font-semibold">Change password</h2>
            <p class="text-muted-foreground mt-2 text-sm">Confirm your current password. Changing it signs you out of provider sessions and revokes connected application tokens. Applications may keep their own session until they next check with this provider.</p>
            <div id="account-settings-mount" data-password-url="{{ route('settings.password') }}" data-login-url="{{ route('login') }}"></div>
            <noscript><p class="mt-4">Enable JavaScript to change your password.</p></noscript>
        </section>
        <section aria-labelledby="passkeys-heading" class="rounded-xl border border-border bg-card p-6">
            <h2 id="passkeys-heading" class="text-lg font-semibold">Passkeys</h2>
            <p class="text-muted-foreground my-3 text-sm">Passkeys belong to the domain where you register them. They are never copied between providers. Keep access to your email or password before removing a passkey. A passkey sign-in may require signing in again on your next visit.</p>
            <x-ui.button :href="route('settings.passkeys')" variant="outline">Manage passkeys</x-ui.button>
        </section>
        <section aria-labelledby="recovery-heading">
            <h2 id="recovery-heading" class="text-lg font-semibold">Trouble signing in?</h2>
            <p class="text-muted-foreground mt-2 text-sm">Use an emailed sign-in code from the sign-in page if you can access your account email. If you forgot your password, an administrator must reset it. If you cannot access your email, contact an administrator. Name and email changes are administrator-managed.</p>
            <a href="{{ route('login') }}" class="mt-3 inline-block text-sm underline">Go to sign in</a>
        </section>
    </main>
@endsection

@push('scripts')
    @vite(['resources/js/account-settings.tsx'])
@endpush
