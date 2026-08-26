@extends('layouts.app')

@section('title', 'Application access unavailable')

@section('content')
    <div class="mx-auto max-w-lg px-4 py-12">
        <div class="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
            <h1 class="mb-2 text-2xl font-bold">Access to {{ $clientName }} is unavailable</h1>
            <p class="text-sm text-gray-600">
                Your account is not currently allowed to sign in to this application. Contact an identity administrator if you need access.
            </p>
        </div>
    </div>
@endsection
