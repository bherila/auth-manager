@extends('layouts.app')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('title', 'Directory administration')

@section('content')
    <div id="directory-admin-mount">
        <main class="mx-auto max-w-6xl px-4 py-10">
            <p class="sr-only">
                A selected grant permits OAuth, but never creates a record inside a connected application.
            </p>
            <div class="bg-card border-border h-48 animate-pulse rounded-xl border" aria-hidden="true"></div>
        </main>
    </div>
@endsection

@push('scripts')
    @vite(['resources/js/admin-directory.tsx'])
@endpush
