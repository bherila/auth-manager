@extends('layouts.app')
@section('title', 'Invitation accepted')
@section('content')
<main class="mx-auto max-w-xl space-y-5 px-6 py-10">
    <h1 class="text-2xl font-semibold">Invitation accepted</h1>
    <p role="status">You can now sign in to {{ $result['application'] }} with this account.</p>
    @unless($result['roles_applied'])
        <p>The access the invitation offered could not be set up yet. The people who manage {{ $result['application'] }} can see this and give you access.</p>
    @endunless
    @if(is_string($result['launch_url']) && str_starts_with($result['launch_url'], 'https://'))
        <a class="inline-block rounded border px-4 py-2" href="{{ $result['launch_url'] }}">Open {{ $result['application'] }}</a>
    @endif
    <a class="underline" href="/">Go to your account</a>
</main>
@endsection
