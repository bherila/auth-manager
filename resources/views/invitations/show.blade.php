@extends('layouts.app')
@section('title', 'Invitation')
@section('content')
<main class="mx-auto max-w-xl space-y-5 px-6 py-10">
    <h1 class="text-2xl font-semibold">You're invited to {{ $applicationName }}</h1>
    <p>This invitation is for <strong>{{ $invitation->email }}</strong>. It expires on {{ $invitation->expires_at->toDateString() }}.</p>
    @if(session('invitation_error'))<p role="alert" class="rounded border p-3">{{ session('invitation_error') }}</p>@endif
    @if($errors->any())
        <ul role="alert" class="list-disc rounded border p-3 pl-8">
            @foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach
        </ul>
    @endif
    @switch($state)
        @case('accept')
            <form method="post" action="{{ route('invitations.accept', $token) }}" class="space-y-3">
                @csrf
                <p>You're signed in as {{ $invitation->email }}. Accepting lets this account sign in to {{ $applicationName }}.</p>
                <button class="rounded border px-4 py-2">Accept invitation</button>
            </form>
            @break
        @case('sign_in')
            <p>An account with this address already exists. Sign in to it to accept.</p>
            <a class="inline-block rounded border px-4 py-2" href="{{ route('invitations.sign-in', $token) }}">Sign in as {{ $invitation->email }}</a>
            @break
        @case('wrong_account')
            <p role="alert">You're signed in as a different account. Only the account for {{ $invitation->email }} can accept this invitation.</p>
            <form method="post" action="{{ route('invitations.sign-out', $token) }}">
                @csrf
                <button class="rounded border px-4 py-2">Sign out and continue</button>
            </form>
            @break
        @case('ambiguous')
            <p role="alert">This invitation can't be accepted here: more than one account matches its address. Contact the person who invited you.</p>
            @break
        @case('disabled')
            <p role="alert">The account for this address can't sign in, so it can't accept this invitation. Contact the person who invited you.</p>
            @break
        @default
            <form method="post" action="{{ route('invitations.accept', $token) }}" class="space-y-4">
                @csrf
                <p>Create your account to accept. You'll sign in with this email address.</p>
                <label class="block">Email <input type="email" value="{{ $invitation->email }}" readonly class="rounded border bg-background p-2"></label>
                <label class="block">Name <input type="text" name="name" required maxlength="255" autocomplete="name" value="{{ old('name') }}" class="rounded border bg-background p-2"></label>
                <label class="block">Password <input type="password" name="password" required minlength="12" autocomplete="new-password" class="rounded border bg-background p-2"></label>
                <label class="block">Confirm password <input type="password" name="password_confirmation" required minlength="12" autocomplete="new-password" class="rounded border bg-background p-2"></label>
                <p class="text-sm">At least 12 characters.</p>
                <button class="rounded border px-4 py-2">Create account and accept</button>
            </form>
    @endswitch
</main>
@endsection
