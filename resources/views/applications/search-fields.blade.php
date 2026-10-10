{{-- The searches in force, carried by a form so its result stays within them. $except names one to leave out. --}}
@foreach($searches as $field => $query)
    @if($field !== ($except ?? null))
        <input type="hidden" name="{{ $field }}" value="{{ $query }}">
    @endif
@endforeach
