@extends('layouts.app')

@section('title', 'Sign in')

@section('content')
    <main class="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
        <h1 class="text-2xl font-semibold tracking-tight">{{ config('app.name') }}</h1>
        <p class="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
            Sign in to continue to the application that sent you here.
        </p>
        @auth
            @if (auth()->user()->canLogin() && auth()->user()->hasRole('admin'))
                <a
                    href="{{ route('admin.users') }}"
                    class="bg-primary text-primary-foreground mt-6 inline-flex w-fit rounded-md px-4 py-2 text-sm font-medium"
                >
                    Directory administration
                </a>
            @endif
        @endauth
    </main>
@endsection
