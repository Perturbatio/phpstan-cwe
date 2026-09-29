{{-- @phpstan-ignore phpstanCwe.cwe79 (The value is trusted.) --}}
{!! $trusted !!}
{!! $unsafe !!} {{-- Report: This raw echo has no ignore comment. --}}
<p>{{-- @phpstan-ignore phpstanCwe.cwe79 --}} {!! $safeHtml !!}</p>
{!! $unsafeAgain !!} {{-- Report: The same-line ignore does not apply here. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
<p>Other output</p>
{!! $notAdjacent !!} {{-- Report: The comment is not next to this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}

{!! $afterBlankLine !!} {{-- Report: The blank line stops the ignore. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{{ $escaped }} {{-- No raw echo matches the ignore comment. --}}
{!! $stillUnsafe !!} {{-- Report: An escaped echo cannot use the ignore. --}}
@verbatim
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
@endverbatim
{!! $outsideVerbatim !!} {{-- Report: A verbatim comment cannot hide this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe89 --}}
{!! $wrongIdentifier !!} {{-- Report: A different identifier cannot hide this echo. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{!! 'Fixed text' !!} {{-- No raw echo with a value matches the ignore. --}}
{!! $afterFixedText !!} {{-- Report: The ignore does not apply here. --}}
{{-- @phpstan-ignore phpstanCwe.cwe79 --}} {!! $first !!} {!! $second !!} {{-- Report: The ignore hides only the first echo. --}}
@{{-- @phpstan-ignore phpstanCwe.cwe79 --}}
{!! $afterEscapedComment !!} {{-- Report: The escaped comment is text, not an ignore. --}}
