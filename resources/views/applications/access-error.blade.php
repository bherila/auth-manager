@extends('layouts.app')
@section('title', 'Application access')
@section('content')
<main class="mx-auto max-w-2xl space-y-5 px-6 py-10">
    <h1 class="text-2xl font-semibold">Application access</h1>
    <p role="alert">{{ $message }}</p>
    <a class="underline" href="{{ route('applications.access', $application) }}">Reload current access</a>
    <a class="ml-4 underline" href="/">Back to your account</a>
</main>
@endsection
