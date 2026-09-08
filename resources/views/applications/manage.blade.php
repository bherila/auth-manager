@extends('layouts.app')
@section('title', 'Application access')
@section('content')
<main class="mx-auto max-w-2xl space-y-5 px-6 py-10">
    <a class="underline" href="/">Back to your account</a>
    <h1 class="text-2xl font-semibold">Application access</h1>
    <p>Choose an application to check the access you are authorized to manage. Each application enforces its own administrator and workspace permissions.</p>
    <ul class="space-y-3">
        @forelse($applications as $application)
            <li><a class="underline" href="{{ route('applications.access', $application['key']) }}">{{ $application['name'] }}</a></li>
        @empty
            <li>No application access integrations are available for this account.</li>
        @endforelse
    </ul>
</main>
@endsection
