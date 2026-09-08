@php
    $formId = $application?->id ?? 'new';
    $submitted = (string) old('_application_form') === (string) $formId;
    $mappedIds = $submitted ? old('client_ids', []) : ($application?->clients->modelKeys() ?? []);
    $availableIds = $clients->modelKeys();
    $unavailableMappings = $application?->clients->filter(fn ($client) => ! in_array($client->id, $availableIds, true)) ?? collect();
@endphp
<form method="POST" action="{{ $application ? route('admin.applications.update', $application) : route('admin.applications.store') }}" class="border-border bg-card space-y-4 rounded-xl border p-5">
    @csrf
    <input type="hidden" name="_application_form" value="{{ $formId }}" />
    @if ($application) @method('PUT') @endif
    <h2 class="text-lg font-semibold">{{ $application ? $application->name : 'Register an application' }}</h2>
    @if ($application)
        <p class="text-muted-foreground text-sm">Stable key: {{ $application->key }}</p>
    @else
        <div class="space-y-2">
            <x-ui.label :for="'key-'.$formId">Stable key</x-ui.label>
            <x-ui.input :id="'key-'.$formId" name="key" :value="$submitted ? old('key') : null" required maxlength="64" pattern="[a-z][a-z0-9-]*" placeholder="example-app" />
            <p class="text-muted-foreground text-xs">Lowercase letters, digits and hyphens; starts with a letter. The key cannot be renamed.</p>
        </div>
    @endif
    <div class="space-y-2">
        <x-ui.label :for="'app-name-'.$formId">Application name</x-ui.label>
        <x-ui.input :id="'app-name-'.$formId" name="name" :value="$submitted ? old('name') : $application?->name" required maxlength="255" />
    </div>
    <div class="space-y-2">
        <x-ui.label :for="'launch-'.$formId">HTTPS launch URL</x-ui.label>
        <x-ui.input :id="'launch-'.$formId" name="launch_url" type="url" :value="$submitted ? old('launch_url') : $application?->launch_url" required maxlength="2048" placeholder="https://app.example.test" />
        <p class="text-muted-foreground text-xs">Use the application's trusted landing page without credentials, query parameters or a fragment.</p>
    </div>
    <input type="hidden" name="enabled" value="0" />
    <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" value="1" @checked($submitted ? old('enabled') : $application?->enabled) /> Enabled for launch navigation</label>
    <fieldset class="space-y-2">
        <legend class="font-medium">Mapped static OAuth clients</legend>
        <p class="text-muted-foreground text-xs">Only people with an existing grant to a mapped, active client can see this application. Dynamically registered clients cannot be mapped.</p>
        @foreach ($clients as $client)
            <label class="flex items-center gap-2 text-sm"><input type="checkbox" name="client_ids[]" value="{{ $client->id }}" @checked(in_array($client->id, $mappedIds, true)) /> {{ $client->name }} <span class="text-muted-foreground">({{ $client->id }})</span></label>
        @endforeach
        @if ($clients->isEmpty())
            <p class="text-muted-foreground text-sm">No eligible static OAuth clients are registered.</p>
        @endif
        @foreach ($unavailableMappings as $client)
            <p class="text-destructive text-sm">{{ $client->name }} is no longer eligible. Saving removes this mapping.</p>
        @endforeach
    </fieldset>
    <x-ui.button type="submit">{{ $application ? 'Save registration' : 'Register application' }}</x-ui.button>
</form>
