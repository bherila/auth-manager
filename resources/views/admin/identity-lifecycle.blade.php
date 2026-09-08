@extends('layouts.app')

@section('title', 'Identity lifecycle')

@push('head')
    <meta name="robots" content="noindex, nofollow, noarchive" />
@endpush

@section('content')
    <main class="mx-auto max-w-4xl space-y-6 px-6 py-10">
        <a href="{{ route('admin.users') }}" class="text-sm underline">Directory administration</a>
        <div>
            <h1 class="text-2xl font-semibold">Identity lifecycle</h1>
            <p class="text-muted-foreground mt-2 text-sm">Provider deletion and application reconciliation are separate steps. Provider purge or an expired retention window never means an application acknowledged completion.</p>
            <p class="text-muted-foreground mt-2 text-sm">Application names below are snapshots taken when deletion started. This page does not verify existing application browser sessions.</p>
        </div>
        @forelse ($tombstones as $tombstone)
            <section class="border-border bg-card space-y-4 rounded-xl border p-5">
                <h2 class="text-lg font-semibold">Subject {{ $tombstone['subject'] }}</h2>
                <dl class="grid gap-2 text-sm sm:grid-cols-2">
                    <div><dt class="font-medium">Deletion accepted</dt><dd>{{ $tombstone['tombstoned_at'] }}</dd></div>
                    <div><dt class="font-medium">Retention deadline</dt><dd>{{ $tombstone['purge_after'] }}{{ $tombstone['retention_expired'] ? ' (expired)' : '' }}</dd></div>
                    <div><dt class="font-medium">Provider record</dt><dd>{{ $tombstone['provider_purged_at'] ? 'Purged at '.$tombstone['provider_purged_at'] : 'Retained' }}</dd></div>
                    <div><dt class="font-medium">Application reconciliation</dt><dd>{{ $tombstone['pending_count'] }} pending of {{ count($tombstone['applications']) }} expected</dd></div>
                </dl>
                @if ($tombstone['applications'] === [])
                    <p class="text-muted-foreground text-sm">No applications were expected in the deletion snapshot.</p>
                @else
                    <ul class="space-y-2 text-sm">
                        @foreach ($tombstone['applications'] as $application)
                            <li class="border-border rounded border p-3">
                                <span class="font-medium">{{ $application['name'] }}</span>
                                <span class="text-muted-foreground break-all">({{ $application['id'] }})</span>
                                <span> — {{ $application['acknowledged_at'] ? 'Acknowledged at '.$application['acknowledged_at'] : 'Pending acknowledgement' }}</span>
                            </li>
                        @endforeach
                    </ul>
                @endif
            </section>
        @empty
            <p class="text-muted-foreground">No identity deletions have been recorded.</p>
        @endforelse
        {{ $tombstones->links() }}
    </main>
@endsection
