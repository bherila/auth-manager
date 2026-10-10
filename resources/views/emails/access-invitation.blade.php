<x-mail::message>
# You're invited to {{ $applicationName }}

Someone who manages {{ $applicationName }} invited this email address to use it. {{ $applicationName }} uses {{ $serviceName }} for sign-in.

Open the link to accept. If you already have an account with this address, sign in to it; otherwise you can create one.

<x-mail::button :url="$link">
Accept the invitation
</x-mail::button>

The link works once and expires in {{ $expiresInDays }} days. If you weren't expecting this, you can ignore this email.
</x-mail::message>
