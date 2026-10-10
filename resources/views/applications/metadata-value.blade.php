@if(is_string($value))<time datetime="{{ $value }}">{{ \App\Support\DelegatedMetadata::display($value) }}</time>@else Not recorded @endif
