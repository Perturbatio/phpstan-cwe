{{-- This raw echo is in a comment. It must not cause a report: {!! $ignored !!} --}}
{{ $escaped }} {{-- No report: Blade escapes this value. --}}
{!! $name !!} {{-- Report: Blade prints the value without an escape call. --}}
@{!! $literalDirective !!} {{-- No report: Blade prints the directive as text. --}}
{!! 'Fixed text' !!} {{-- No report: This text does not depend on a value. --}}
@verbatim
{!! $example !!} {{-- No report: This block prints the text as written. --}}
@endverbatim
<p>{!!
    $comment
!!}</p> {{-- Report: This raw echo starts on the line above. --}}
{!! "Hello $name" !!} {{-- Report: The quoted text uses a value. --}}
