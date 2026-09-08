@extends('layouts.app')

@section('title', 'Application registry')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('content')
    <main class="mx-auto max-w-4xl space-y-6 px-6 py-10">
        <a href="{{ route('admin.users') }}" class="text-sm underline">Directory administration</a>
        <div>
            <h1 class="text-2xl font-semibold">Application registry</h1>
            <p class="text-muted-foreground mt-2 text-sm">Register trusted applications for this identity provider. Registration does not create OAuth clients, grant sign-in, or change application permissions.</p>
            <p class="text-muted-foreground mt-2 text-sm">Launch links currently use {{ $launchEnabled ? 'the enabled registrations below' : 'legacy static-client navigation until the registry rollout is enabled' }}.</p>
        </div>
        @if (session('status'))
            <p role="status" class="border-border rounded border p-3">{{ session('status') }}</p>
        @endif
        @if ($errors->any())
            <div role="alert" class="border-destructive rounded border p-3">
                <p class="font-medium">The registration was not saved.</p>
                <ul>@foreach ($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul>
            </div>
        @endif
        @include('admin.application-form', ['application' => null])
        @foreach ($applications as $application)
            @include('admin.application-form', ['application' => $application])
        @endforeach
    </main>
@endsection
