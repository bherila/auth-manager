{{-- Offered only while the application's read says the removal would succeed (allowed_edits.remove). --}}
<div class="space-y-3 rounded border p-4">
    <h3 class="font-semibold">Remove from this application</h3>
    <p>This removes the access you manage for this account in {{ $application->name }}: {{ $accountOnly ? 'application administration' : 'its workspace memberships and application administration' }}. Access you cannot manage here is not changed.</p>
    <p>The account and its history stay in {{ $application->name }}. Nothing is deleted, and you can give access again later.</p>
    <form method="post" action="{{ route('applications.access.remove', $application->key) }}" class="space-y-3">
        @csrf
        @include('applications.operation-id')
        @include('applications.search-fields')
        <input type="hidden" name="subject" value="{{ $subject }}">
        <input type="hidden" name="expected_revision" value="{{ $state['revision'] }}">
        <label class="flex items-start gap-2">
            <input type="checkbox" name="confirm_removal" value="1" required class="mt-1">
            <span>I understand this removes this account's access to {{ $application->name }} and keeps the account and its history.</span>
        </label>
        <button class="rounded border px-4 py-2">Remove from this application</button>
        <p class="text-sm">Removing requires a credential check within the last five minutes.</p>
    </form>
</div>
