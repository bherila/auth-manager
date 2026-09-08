@props(['url'])
@php($branding = app(\App\Support\DeploymentBranding::class))
<tr>
<td class="header">
<a href="{{ $url }}" style="display: inline-block;">
@if ($branding->enabled())
@if ($logo = $branding->emailLogo())
<img src="{{ $logo }}" alt="" style="display: block; max-width: 192px; max-height: 64px; margin: 0 auto 12px;">
@endif
{{ config('app.name') }}
@elseif (trim($slot) === 'Laravel')
<img src="https://laravel.com/img/notification-logo-v2.1.png" class="logo" alt="Laravel Logo">
@else
{!! $slot !!}
@endif
</a>
</td>
</tr>
