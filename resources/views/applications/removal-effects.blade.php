{{-- One membership's removal_effects, as the application disclosed them: each label beside its count,
     never summed with another membership's, never inflected into a sentence. Labels are the
     application's plain text, escaped and direction-isolated. --}}
<ul @isset($id) id="{{ $id }}" @endisset class="list-disc pl-6">
    @foreach($effects as $effect)
        <li><bdi dir="auto">{{ $effect['label'] }}</bdi>: {{ $effect['count'] }}</li>
    @endforeach
</ul>
