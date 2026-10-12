<x-mail::message>
# Your code to join {{ $applicationName }}

Someone is accepting an invitation to {{ $applicationName }} for this email address and creating a {{ $serviceName }} account for it. Enter this code on the invitation page to confirm the address is yours:

<x-mail::panel>
**{{ $code }}**
</x-mail::panel>

The code expires in {{ $expiresInMinutes }} minutes and works once. If you didn't ask for it, ignore this email: no account is created without the code. Never share it with anyone.
</x-mail::message>
