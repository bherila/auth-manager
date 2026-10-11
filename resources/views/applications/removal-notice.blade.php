{{-- access.removal_notice: the application's context for a removal, never a further deletion. --}}
@isset($state['access']['removal_notice'])
    <p>{{ $application->name }} notes: <bdi dir="auto">{{ $state['access']['removal_notice'] }}</bdi></p>
@endisset
