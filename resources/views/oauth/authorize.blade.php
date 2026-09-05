@extends('layouts.app')

@section('title', 'Authorize application')

@section('content')
    <main class="mx-auto flex min-h-screen max-w-lg flex-col justify-center px-4 py-10 sm:px-6">
        <div class="bg-card text-card-foreground border-border rounded-xl border p-6 shadow-sm sm:p-8">
            <h1 class="text-2xl font-semibold tracking-tight">Authorize {{ $client->name }}</h1>
            <p class="text-muted-foreground mt-2 text-sm">This application is requesting access to your account identity.</p>

            <div class="mt-6 flex flex-wrap gap-3">
                <form method="POST" action="{{ route('passport.authorizations.approve') }}">
                    @csrf
                    <input type="hidden" name="state" value="{{ $request->state }}" />
                    <input type="hidden" name="client_id" value="{{ $client->getKey() }}" />
                    <input type="hidden" name="auth_token" value="{{ $authToken }}" />
                    <x-ui.button type="submit" autofocus>Continue</x-ui.button>
                </form>

                <form method="POST" action="{{ route('passport.authorizations.deny') }}">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="state" value="{{ $request->state }}" />
                    <input type="hidden" name="client_id" value="{{ $client->getKey() }}" />
                    <input type="hidden" name="auth_token" value="{{ $authToken }}" />
                    <x-ui.button type="submit" variant="outline">Cancel</x-ui.button>
                </form>
            </div>
        </div>
    </main>
@endsection
