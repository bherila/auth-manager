{{-- Invitations to this application. Included by applications.access, whose $roleLabels, $workspaceLabels,
     $capabilities, $workspaces and $accountOnly it uses. --}}
@php
    $outcomeLabels = [
        'inviter_not_authorized' => 'the inviter can no longer give this access',
        'roles_not_offered' => 'the application no longer offers this access',
        'provisioning_unavailable' => 'the application did not offer to create the account',
        'not_authorized' => 'the application refused the inviter',
        'revision_conflict' => 'the account changed while access was being applied',
        'invalid_request' => 'the application could not apply this access',
    ];
@endphp
<section class="space-y-3 rounded border p-4" aria-labelledby="invitations-heading">
    <h2 id="invitations-heading" class="text-lg font-semibold">Invitations</h2>
    @if(session('invitation_notice'))<p role="status" class="rounded border p-3">{{ session('invitation_notice') }}</p>@endif
    @if(session('invitation_link'))
        <div class="space-y-2 rounded border p-3">
            <p role="alert">The invitation email could not be sent. Share this link with the person yourself, privately: whoever opens it can accept the invitation.</p>
            <label class="block">Invitation link, shown only now.
                <input type="text" readonly value="{{ session('invitation_link') }}" class="mt-1 w-full rounded border bg-background p-2 font-mono text-sm">
            </label>
            <p class="text-sm">It works once, for the invited address only, and expires in {{ config('delegated-access.invitations.expires_after_days', 7) }} days.</p>
        </div>
    @endif
    @if($invitations['form'])
        <form method="post" action="{{ route('applications.access.invitations.store', $application->key) }}" class="space-y-4">
            @csrf
            <p>Invite someone by email. They accept by signing in with that address, or by creating an account with it, and then the application applies the access you choose, as though you made the change at that moment.</p>
            <label class="block">Email <input type="email" name="email" required maxlength="255" autocomplete="off" class="rounded border bg-background p-2"></label>
            @if($accountOnly)
                @include('applications.provision-admin-choice')
            @else
                @if($capabilities['controls']['application_admin'])
                    <label class="block">Application administrator
                        <select name="application_admin" required class="rounded border bg-background p-2">
                            <option value="">Choose</option>
                            <option value="0">No</option>
                            <option value="1">Yes</option>
                        </select>
                    </label>
                @endif
                <fieldset class="space-y-2">
                    <legend>Workspace access (choose at least one{{ $capabilities['controls']['application_admin'] ? ', unless they will be an application administrator' : '' }})</legend>
                    @for($row = 0; $row < 3; $row++)
                        <div class="flex flex-wrap gap-3">
                            <label>Workspace
                                <select name="workspaces[{{ $row }}][id]" class="rounded border bg-background p-2">
                                    <option value="">No workspace</option>
                                    @foreach($workspaces['workspaces'] as $workspace)
                                        <option value="{{ $workspace['id'] }}">{{ $workspace['label'] }}</option>
                                    @endforeach
                                </select>
                            </label>
                            <label>Role
                                <select name="workspaces[{{ $row }}][role]" class="rounded border bg-background p-2">
                                    <option value="">Choose a role</option>
                                    @foreach($capabilities['controls']['workspace_roles'] as $role)
                                        <option value="{{ $role['id'] }}">{{ $role['label'] }}</option>
                                    @endforeach
                                </select>
                            </label>
                        </div>
                    @endfor
                </fieldset>
            @endif
            <button class="rounded border px-4 py-2">Send invitation</button>
            <p class="text-sm">Sending requires a credential check within the last five minutes. The answer is the same whether or not the address already has an account.</p>
        </form>
    @elseif($invitations['unavailable'])
        <p>{{ $invitations['unavailable'] }}</p>
    @endif
    @if($invitations['list']->isEmpty())
        <p>No invitations to this application yet.</p>
    @else
        <ul class="space-y-3">
            @foreach($invitations['list'] as $invitation)
                @php($status = $invitation->status())
                <li class="space-y-1 rounded border p-3">
                    <p><span class="font-medium">{{ $invitation->email }}</span>,
                        invited by {{ $invitation->inviter?->name ?? 'a former manager' }} on {{ $invitation->created_at->toDateString() }}</p>
                    <p class="text-sm">Access:
                        {{ collect([
                            ($invitation->access['application_admin'] ?? false) ? 'Application administrator' : null,
                            ...array_map(fn (array $m): string => ($workspaceLabels[$m['id']] ?? $m['id']).': '.($roleLabels[$m['role']] ?? $m['role']), $invitation->access['workspaces'] ?? []),
                        ])->filter()->implode('; ') ?: 'An account, without administration' }}</p>
                    <p>
                        @switch($status)
                            @case('pending') Pending until {{ $invitation->expires_at->toDateString() }} @break
                            @case('expired') Expired @break
                            @case('revoked') Revoked @break
                            @default
                                @if($invitation->roles_status === 'applied')
                                    Accepted; access applied
                                @elseif($invitation->roles_status === 'not_applied')
                                    <strong>Accepted; roles not applied</strong>
                                    ({{ $outcomeLabels[$invitation->roles_outcome] ?? 'the application did not apply this access' }}). The person can sign in to the application; give them access above.
                                @else
                                    <strong>Accepted; roles not confirmed</strong>.
                                    The application did not confirm the change. Review this person's current access before changing it.
                                @endif
                        @endswitch
                    </p>
                    @if($invitations['can_invite'] && in_array($status, ['pending', 'expired'], true))
                        <div class="flex flex-wrap gap-3">
                            <form method="post" action="{{ route('applications.access.invitations.resend', [$application->key, $invitation->id]) }}">
                                @csrf
                                <button class="underline">Send again with a new link</button>
                            </form>
                            @if($status === 'pending')
                                <form method="post" action="{{ route('applications.access.invitations.revoke', [$application->key, $invitation->id]) }}">
                                    @csrf
                                    <button class="underline">Revoke</button>
                                </form>
                            @endif
                        </div>
                    @endif
                </li>
            @endforeach
        </ul>
    @endif
</section>
