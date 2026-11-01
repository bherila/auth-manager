@if(is_string($value))<time datetime="{{ $value }}">{{ \BWH\AuthManager\Support\DelegatedMetadata::display($value) }}</time>@else Not recorded @endif
