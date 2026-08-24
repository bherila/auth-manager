@extends('layouts.app')

@section('title', 'Authorize application')

@section('content')
    <div class="mx-auto max-w-lg px-4 py-12">
        <div class="rounded-lg border border-gray-200 bg-white p-6 shadow-sm">
            <h1 class="mb-2 text-2xl font-bold">Authorize {{ $client->name }}</h1>
            <p class="mb-6 text-sm text-gray-600">This application is requesting access to your account identity.</p>

            <div class="flex gap-3">
                <form method="POST" action="{{ route('passport.authorizations.approve') }}">
                    @csrf
                    <input type="hidden" name="state" value="{{ $request->state }}" />
                    <input type="hidden" name="client_id" value="{{ $client->getKey() }}" />
                    <input type="hidden" name="auth_token" value="{{ $authToken }}" />
                    <button type="submit" class="rounded bg-blue-600 px-4 py-2 font-medium text-white">Continue</button>
                </form>

                <form method="POST" action="{{ route('passport.authorizations.deny') }}">
                    @csrf
                    @method('DELETE')
                    <input type="hidden" name="state" value="{{ $request->state }}" />
                    <input type="hidden" name="client_id" value="{{ $client->getKey() }}" />
                    <input type="hidden" name="auth_token" value="{{ $authToken }}" />
                    <button type="submit" class="rounded border border-gray-300 px-4 py-2 font-medium">Cancel</button>
                </form>
            </div>
        </div>
    </div>
@endsection
