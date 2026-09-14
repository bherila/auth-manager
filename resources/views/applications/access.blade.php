@extends('layouts.app')
@section('title', 'Application access')
@section('content')
@php
    $roleLabels = $version === 2 ? array_column($capabilities['controls']['workspace_roles'], 'label', 'id') : [];
    $workspaceLabels = array_column($workspaces['workspaces'], 'label', 'id');
@endphp
<main class="mx-auto max-w-3xl space-y-6 px-6 py-10">
    <a class="underline" href="/">Back to your account</a>
    <h1 class="text-2xl font-semibold">{{ $application->name }} access</h1>
    <p>The application decides which accounts and workspaces you can manage. Provider administration does not grant application permissions.</p>
    @if(session('status'))<p role="status">{{ session('status') }}</p>@endif
    @if($saved)<p role="status" class="rounded border p-3">The application confirmed the access update.</p>@endif
    @if(session('access_failure'))<p role="alert" class="rounded border p-3">{{ session('access_failure') }}</p>@endif
    @if($errors->any())
        <ul role="alert" class="list-disc rounded border p-3 pl-8">
            @foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach
        </ul>
    @endif
    <section class="space-y-3 rounded border p-4">
        <h2 class="text-lg font-semibold">Choose an account</h2>
        <form method="post" action="{{ route('applications.access.browse', $application->key) }}" class="flex flex-wrap gap-3">
            @csrf
            <label>Account
                <select name="subject" required class="rounded border bg-background p-2">
                    <option value="">Select an account</option>
                    @foreach($subjects['subjects'] as $candidate)
                        <option value="{{ $candidate['subject'] }}" @selected($candidate['subject'] === $subject)>{{ $candidate['label'] }}</option>
                    @endforeach
                </select>
            </label>
            <button class="rounded border px-3 py-2">Review access</button>
        </form>
        @if($subjects['next_cursor'])
            <form method="post" action="{{ route('applications.access.browse', $application->key) }}">
                @csrf
                <input type="hidden" name="subject_cursor" value="{{ $subjects['next_cursor'] }}">
                <button class="underline">More accounts</button>
            </form>
        @endif
    </section>
    @if($directory !== null)
        <section class="space-y-3 rounded border p-4">
            <h2 class="text-lg font-semibold">Give access to someone new</h2>
            <p>People who can sign in to {{ $application->name }} through this account service. Choosing one reviews their access in the application, which decides whether you may create their account.</p>
            <form method="post" action="{{ route('applications.access.browse', $application->key) }}" class="flex flex-wrap gap-3">
                @csrf
                <label>Search people <input type="search" name="directory_search" value="{{ $directorySearch }}" maxlength="100" class="rounded border bg-background p-2"></label>
                <button class="rounded border px-3 py-2">Search</button>
            </form>
            @if(count($directory['people']))
                <form method="post" action="{{ route('applications.access.browse', $application->key) }}" class="flex flex-wrap gap-3">
                    @csrf
                    <input type="hidden" name="directory_search" value="{{ $directorySearch }}">
                    <label>Person
                        <select name="subject" required class="rounded border bg-background p-2">
                            <option value="">Select a person</option>
                            @foreach($directory['people'] as $person)
                                <option value="{{ $person['subject'] }}" @selected($person['subject'] === $subject)>{{ $person['name'] }} ({{ $person['email'] }})</option>
                            @endforeach
                        </select>
                    </label>
                    <button class="rounded border px-3 py-2">Review access</button>
                </form>
            @else
                <p>No one who can sign in to this application matches.</p>
            @endif
            @if($directory['next_page'])
                <form method="post" action="{{ route('applications.access.browse', $application->key) }}">
                    @csrf
                    <input type="hidden" name="directory_search" value="{{ $directorySearch }}">
                    <input type="hidden" name="directory_page" value="{{ $directory['next_page'] }}">
                    <button class="underline">More people</button>
                </form>
            @endif
        </section>
    @endif
    @if($state)
        <section class="space-y-3 rounded border p-4">
            <h2 class="text-lg font-semibold">Current access</h2>
            <p>Account reference: {{ $subject }}</p>
            @if(!$state['provisioned'])
                <p>This account has not been provisioned in the application. A sign-in grant does not create an application account.</p>
                @if($version === 2 && $state['allowed_edits']['provision'] && config('delegated-access.writes_enabled'))
                    <form method="post" action="{{ route('applications.access.provision', $application->key) }}" class="space-y-4">
                        @csrf
                        <input type="hidden" name="subject" value="{{ $subject }}">
                        <label class="block">Workspace
                            <select name="new_workspace" required class="rounded border bg-background p-2">
                                <option value="">Select a workspace</option>
                                @foreach($workspaces['workspaces'] as $workspace)
                                    <option value="{{ $workspace['id'] }}">{{ $workspace['label'] }}</option>
                                @endforeach
                            </select>
                        </label>
                        <label class="block">Role
                            <select name="new_role" required class="rounded border bg-background p-2">
                                @foreach($capabilities['controls']['workspace_roles'] as $role)
                                    <option value="{{ $role['id'] }}">{{ $role['label'] }}</option>
                                @endforeach
                            </select>
                        </label>
                        <button class="rounded border px-4 py-2">Create account and give access</button>
                        <p class="text-sm">The application creates this person's account, bound to their sign-in here, with the workspace and role you choose. Saving requires a credential check within the last five minutes.</p>
                    </form>
                    @if($workspaces['next_cursor'])
                        <form method="post" action="{{ route('applications.access.browse', $application->key) }}">
                            @csrf
                            <input type="hidden" name="subject" value="{{ $subject }}">
                            <input type="hidden" name="workspace_cursor" value="{{ $workspaces['next_cursor'] }}">
                            <button class="underline">More workspaces</button>
                        </form>
                    @endif
                @endif
            @else
                <form method="post" action="{{ route('applications.access.update', $application->key) }}" class="space-y-4">
                    @csrf
                    <input type="hidden" name="subject" value="{{ $subject }}">
                    <input type="hidden" name="expected_revision" value="{{ $state['revision'] }}">
                    @if($state['allowed_edits']['application_admin'] && $capabilities['controls']['application_admin'])
                        <label class="block">Application administrator
                            <select name="application_admin" class="rounded border bg-background p-2">
                                <option value="0" @selected(!$state['access']['application_admin'])>No</option>
                                <option value="1" @selected($state['access']['application_admin'])>Yes</option>
                            </select>
                        </label>
                    @else
                        <p>Application administrator: {{ $state['access']['application_admin'] ? 'Yes' : 'No' }} (read-only)</p>
                        <input type="hidden" name="application_admin" value="{{ $state['access']['application_admin'] ? '1' : '0' }}">
                    @endif
                    <h3 class="font-semibold">Workspace access</h3>
                    @if($version === 2)
                        @forelse($state['access']['workspaces'] as $index => $membership)
                            <div class="flex items-center gap-3">
                                <input type="hidden" name="workspaces[{{ $index }}][id]" value="{{ $membership['id'] }}">
                                <label>{{ $workspaceLabels[$membership['id']] ?? $membership['id'] }}
                                    {{-- A current role the application no longer advertises cannot be shown in a select without
                                         the browser choosing another one, so that membership is read-only here. --}}
                                    @if($state['allowed_edits']['workspaces'] && $membership['editable'] && array_key_exists($membership['role'], $roleLabels))
                                        <select name="workspaces[{{ $index }}][role]" class="rounded border bg-background p-2">
                                            @foreach($capabilities['controls']['workspace_roles'] as $role)
                                                <option value="{{ $role['id'] }}" @selected($membership['role'] === $role['id'])>{{ $role['label'] }}</option>
                                            @endforeach
                                            <option value="">Remove access</option>
                                        </select>
                                    @else
                                        <span>{{ $roleLabels[$membership['role']] ?? $membership['role'] }} (not editable here)</span>
                                        <input type="hidden" name="workspaces[{{ $index }}][role]" value="{{ $membership['role'] }}">
                                    @endif
                                </label>
                            </div>
                        @empty
                            <p>No workspace memberships.</p>
                        @endforelse
                        @if($state['allowed_edits']['workspaces'] && count($state['access']['workspaces']) < 100)
                            <label class="block">Add workspace
                                <select name="new_workspace" class="rounded border bg-background p-2">
                                    <option value="">No additional workspace</option>
                                    @foreach($workspaces['workspaces'] as $workspace)
                                        @if(!in_array($workspace['id'], array_column($state['access']['workspaces'], 'id'), true))
                                            <option value="{{ $workspace['id'] }}">{{ $workspace['label'] }}</option>
                                        @endif
                                    @endforeach
                                </select>
                            </label>
                            <label class="block">New workspace role
                                <select name="new_role" class="rounded border bg-background p-2">
                                    @foreach($capabilities['controls']['workspace_roles'] as $role)
                                        <option value="{{ $role['id'] }}">{{ $role['label'] }}</option>
                                    @endforeach
                                </select>
                            </label>
                        @endif
                    @else
                        @forelse($state['access']['workspaces'] as $index => $membership)
                            <div class="flex items-center gap-3">
                                <input type="hidden" name="workspaces[{{ $index }}][id]" value="{{ $membership['id'] }}">
                                <label>{{ $membership['id'] }}
                                    @if($state['allowed_edits']['workspaces'] && in_array($membership['permission'], $capabilities['controls']['workspace_permissions'], true))
                                        <select name="workspaces[{{ $index }}][permission]" class="rounded border bg-background p-2">
                                            @foreach($capabilities['controls']['workspace_permissions'] as $permission)
                                                <option value="{{ $permission }}" @selected($membership['permission'] === $permission)>{{ $permission === 'write' ? 'Read and write' : 'Read only' }}</option>
                                            @endforeach
                                            <option value="none">Remove access</option>
                                        </select>
                                    @else
                                        <span>{{ $membership['permission'] }}</span>
                                        <input type="hidden" name="workspaces[{{ $index }}][permission]" value="{{ $membership['permission'] }}">
                                    @endif
                                </label>
                            </div>
                        @empty
                            <p>No workspace memberships.</p>
                        @endforelse
                        @if($state['allowed_edits']['workspaces'] && count($capabilities['controls']['workspace_permissions']) && count($state['access']['workspaces']) < 100)
                            <label class="block">Add workspace
                                <select name="new_workspace" class="rounded border bg-background p-2">
                                    <option value="">No additional workspace</option>
                                    @foreach($workspaces['workspaces'] as $workspace)
                                        @if(!in_array($workspace['id'], array_column($state['access']['workspaces'], 'id'), true))
                                            <option value="{{ $workspace['id'] }}">{{ $workspace['label'] }}</option>
                                        @endif
                                    @endforeach
                                </select>
                            </label>
                            <label class="block">New workspace permission
                                <select name="new_permission" class="rounded border bg-background p-2">
                                    @foreach($capabilities['controls']['workspace_permissions'] as $permission)
                                        <option value="{{ $permission }}">{{ $permission === 'write' ? 'Read and write' : 'Read only' }}</option>
                                    @endforeach
                                </select>
                            </label>
                        @endif
                    @endif
                    @if(count($state['access']['workspaces']) >= 100)
                        <p>Remove and save a workspace membership before adding another.</p>
                    @endif
                    @if(config('delegated-access.writes_enabled') && ($state['allowed_edits']['application_admin'] || $state['allowed_edits']['workspaces']))
                        <button class="rounded border px-4 py-2">Save access</button>
                        <p class="text-sm">Saving requires a credential check within the last five minutes.</p>
                    @else
                        <p>Access changes are unavailable for this account or integration.</p>
                    @endif
                </form>
                @if($workspaces['next_cursor'] && $state['allowed_edits']['workspaces'])
                    <form method="post" action="{{ route('applications.access.browse', $application->key) }}">
                        @csrf
                        <input type="hidden" name="subject" value="{{ $subject }}">
                        <input type="hidden" name="workspace_cursor" value="{{ $workspaces['next_cursor'] }}">
                        <button class="underline">More workspaces (reloads current access)</button>
                    </form>
                @endif
            @endif
        </section>
    @endif
    @if(config('delegated-access.writes_enabled'))
        <section class="space-y-3 rounded border p-4">
            <h2 class="text-lg font-semibold">Confirm your identity before editing</h2>
            <form method="post" action="{{ route('applications.access.confirm', $application->key) }}" class="flex flex-wrap gap-3">
                @csrf
                <label>Current password <input type="password" name="password" required autocomplete="current-password" class="rounded border bg-background p-2"></label>
                <button class="rounded border px-3 py-2">Confirm password</button>
            </form>
            <p>For passkey or email-code sign-in, sign out and sign in again, then return here.</p>
        </section>
    @endif
</main>
@endsection
