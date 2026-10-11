{{-- Offered only while the application's read says the removal would succeed (allowed_edits.remove). --}}
@php($withEffects = array_values(array_filter($state['access']['workspaces'], fn (array $membership): bool => isset($membership['removal_effects']))))
<div class="space-y-3 rounded border p-4">
    <h3 class="font-semibold">Remove from this application</h3>
    <p>This removes the access you manage for this account in {{ $application->name }}: {{ $accountOnly ? 'application administration' : 'its workspace memberships and application administration' }}. Access you cannot manage here is not changed.</p>
    @if($withEffects !== [])
        <p>{{ $application->name }} also removes these records, which exist only because of a membership:</p>
        <dl class="space-y-2">
            @foreach($withEffects as $membership)
                <div>
                    <dt class="font-semibold"><bdi dir="auto">{{ $workspaceLabels[$membership['id']] ?? $membership['id'] }}</bdi></dt>
                    <dd>@include('applications.removal-effects', ['effects' => $membership['removal_effects']])</dd>
                </div>
            @endforeach
        </dl>
        <p>The account stays in {{ $application->name }}. Apart from the records listed above, nothing is deleted, and you can give access again later.</p>
    @else
        <p>The account and its history stay in {{ $application->name }}. Nothing is deleted, and you can give access again later.</p>
    @endif
    @include('applications.removal-notice')
    <form method="post" action="{{ route('applications.access.remove', $application->key) }}" class="space-y-3">
        @csrf
        @include('applications.operation-id')
        @include('applications.search-fields')
        <input type="hidden" name="subject" value="{{ $subject }}">
        <input type="hidden" name="expected_revision" value="{{ $state['revision'] }}">
        <label class="flex items-start gap-2">
            <input type="checkbox" name="confirm_removal" value="1" required class="mt-1">
            @if($withEffects !== [])
                <span>I understand this removes this account's access to {{ $application->name }} and the records listed above, and keeps the account.</span>
            @else
                <span>I understand this removes this account's access to {{ $application->name }} and keeps the account and its history.</span>
            @endif
        </label>
        <button class="rounded border px-4 py-2">Remove from this application</button>
        <p class="text-sm">Removing requires a credential check within the last five minutes.</p>
    </form>
</div>
