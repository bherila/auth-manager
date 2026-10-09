{{-- Account-only provisioning: whether the new account is an application administrator is always
     chosen, never defaulted. Yes is offered only where the application lets this actor grant it. --}}
<label class="block">Application administrator
    <select name="application_admin" required class="rounded border bg-background p-2">
        <option value="">Choose</option>
        <option value="0">No</option>
        @if($capabilities['controls']['application_admin'])
            <option value="1">Yes</option>
        @endif
    </select>
</label>
