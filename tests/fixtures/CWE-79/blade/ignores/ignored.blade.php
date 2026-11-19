{{-- @phpstan-ignore phpstanCwe.cwe79 (The value is trusted.) --}}
{!! $trusted !!}
{!! $unsafe !!} {{-- Report: This raw echo has no ignore annotation. --}}
<p>{{-- @phpstan-ignore phpstanCwe.cwe79 --}} {!! $safeHtml !!}</p>
{!! $unsafeAgain !!} {{-- Report: The same-line annotation does not apply here. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
<p>Other output</p>
{!! $notAdjacent !!} {{-- Report: The comment is not next to this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}

{!! $afterBlankLine !!} {{-- Report: The blank line stops the annotation. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{{ $escaped }} {{-- No raw echo matches the annotation. --}}
{!! $stillUnsafe !!} {{-- Report: An escaped echo cannot use the annotation. --}}
@verbatim
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
@endverbatim
{!! $outsideVerbatim !!} {{-- Report: A verbatim comment cannot hide this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe89 --}}
{!! $wrongIdentifier !!} {{-- Report: A different identifier cannot hide this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{!! 'Fixed text' !!} {{-- No raw echo with a value matches the annotation. --}}
{!! $afterFixedText !!} {{-- Report: The annotation does not apply here. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}} {!! $first !!} {!! $second !!} {{-- Report: The annotation hides only the first echo. --}}
@{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{!! $afterEscapedComment !!} {{-- Report: The escaped comment above is text, not an ignore annotation. --}}
