# CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program

This rule checks the filename in `include`, `include_once`, `require`, and
`require_once`. It reports a known request value in the filename. It also
reports a dynamic filename when the rule does not find a known request source.
The rule gives each report a **high** severity. The probability score is an
estimate. It is not a measured probability.

The rule gives a score of **95** when a request value supplies all or part of
the filename without change. A copy, concatenation, or string interpolation
does not lower this score. It gives **85** when a function changes the request
value but does not choose from an approved list. It gives **45** after a
numeric cast. It gives **60** when the filename is dynamic and no request
source is known.

Unsafe PHP:

```php
include $_GET['page'];
```

Safe PHP:

```php
$pages = [
    'help' => __DIR__ . '/help.php',
    'home' => __DIR__ . '/home.php',
];
include $pages[$_GET['page']] ?? $pages['home'];
```

The rule checks `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`. It also uses
the [shared Laravel input detector](../../LaravelRequestInput.md) for
supported Laravel input sources.

It follows simple local assignments, copied values, string concatenation,
string interpolation, and `.=`. It checks both results of `??`. It checks
the result expressions in a `match`, not its selector or case labels. A
request value that selects from fixed paths is not part of the filename.
The rule follows list values into a `foreach` value variable. It treats calls
that receive an array as possible changes to that array.

The rule treats the global Laravel `base_path()`, `app_path()`,
`resource_path()`, and `storage_path()` helpers as fixed when their arguments
are fixed. Request input in a helper argument is still reported. Laravel route
parameters in supported route closures are request input. The rule does not
treat a file-existence check as an allow-list.

`basename()`, a numeric cast, and a fixed directory do not limit a filename
to approved files. Use a fixed allow-list to select a path. The rule does not
prove that a path stays inside a directory. It treats an unrecognised
function or method around request input as a change to the value. It does not
check what that function or method does.

## Known limitations

- The rule follows assignments in source order only. It does not merge
  branches, repeat loops, or follow values between functions.
- The rule does not trace values captured by closures or arrow functions.
  It keeps their assignment facts separate from the enclosing scope.
- The rule does not track assignments to properties. It combines array element
  assignments with earlier array values; it does not track each key separately.
- Array references and calls that receive arrays are treated as unknown changes.
  The rule does not follow changes through references or between functions.
- A fixed assignment inside a branch can hide request input when that branch
  does not run.
- The rule does not know whether a dynamic filename is safe. It reports an
  unknown dynamic value for review.
- Other unrecognised functions are unknown, even when their arguments are
  fixed paths. The Laravel path checks assume that the global helpers have
  their standard Laravel behaviour.
- Route parameter checks cover literal route paths and inline closures or arrow
  functions on supported `Route` facade methods. The rule does not follow
  controller actions, dynamic paths, or parameters from route groups.
- A finding can be filtered with `phpstanCwe.minProbability`. Its default is
  `0`.
- For a fingerprint-based ignore annotation, read the
  [shared ignore-annotation guide](../../Ignore/CweIgnore.md).

Full explanation: https://cwe.mitre.org/data/definitions/98.html
