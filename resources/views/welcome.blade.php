@extends('layouts.app')

@section('title', config('app.name'))

@section('content')
    <main class="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
        <h1 class="text-2xl font-semibold tracking-tight">{{ config('app.name') }}</h1>
        @guest
            <p class="text-muted-foreground mt-2 text-sm">
                Sign in to continue to the application that sent you here.
            </p>
            <x-ui.button :href="route('login')" class="mt-6 w-fit">Sign in</x-ui.button>
        @endguest
        @auth
            <p class="text-muted-foreground mt-2 text-sm">
                You are signed in as <span class="text-foreground font-medium">{{ auth()->user()->email }}</span>.
            </p>
            <div class="mt-6 flex flex-wrap gap-3">
                @if (auth()->user()->canLogin())
                    <x-ui.button :href="route('settings.passkeys')">Manage passkeys</x-ui.button>
                @endif
                @if (auth()->user()->canLogin() && auth()->user()->hasRole('admin'))
                    <x-ui.button :href="route('admin.users')" variant="outline">Directory administration</x-ui.button>
                @endif
            </div>
        @endauth
    </main>
@endsection
