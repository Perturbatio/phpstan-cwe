# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

This rule reports calls to PHP `eval()`. It checks input from PHP request
superglobals and, in the Laravel configuration, supported Laravel request
sources. The rule reports all `eval()` calls, including calls with fixed text.
The low score for fixed text is a request to review the code. It does not show
that the code is safe.

Each report uses the stable identifier `phpstanCwe.cwe95`. Severity describes
possible harm. Probability is an estimate of confidence in the finding. It is
not a measured probability of an attack.

## Ratings

| Severity | Probability | Context |
|----------|------------:|---------|
| High | 95% | The rule finds request input in the value passed to `eval()`. |
| High | 90% | The rule follows request input through a local assignment to `eval()`. |
| Medium | 60% | The value is not known to be static, but the rule does not find a supported request source. |
| Low | 30% | The rule does not find request input or another unknown value. Review the evaluated code and its sources. |

The rule does not accept a sanitiser or type as proof that a value is safe.
Do not pass external input to `eval()`.

## Unsafe PHP examples

```php
eval($_GET['code']); // Report: GET input is passed to eval().

$code = $_POST['code'];
$newCode = "return $code;";
eval($newCode); // Report: POST input reaches eval() through local assignments.
```

The basic configuration checks `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`.
The Laravel configuration also uses the shared
[Laravel input detector](../../LaravelRequestInput.md). It checks the global
`request()` helper and supported input reads from `Illuminate\Http\Request`
objects.

## Fixed PHP examples

The rule reports fixed strings at low severity and low probability. This does
not prove that a fixed string is safe.

```php
$code = 'return 1 + 1;';
eval($code); // Report: The rule finds no external input.
```

The rule does not report code that does not call `eval()`:

```php
$code = $_GET['code']; // No report: This is not a dynamic evaluation sink.
```

## Fingerprint-based ignores

The [shared ignore guide](../../Ignore/CweIgnore.md) describes the syntax for all rules.

Each report includes a SHA-256 fingerprint. The fingerprint uses the rule
identifier, file path, function or method name, closure position in source
order, normalised `eval()` expression, and detected input sources.
It does not use a line number or token position. Comments and blank lines
do not change the fingerprint. A detected input source change
creates a different fingerprint. A file rename also creates a different
fingerprint. If you add, remove, or move a closure, review its ignore annotations again.

Each finding has a tip with a copyable ignore comment and its fingerprint.
Only use the ignore after you check that the evaluated code is safe. Replace
`<reason>` with a reason that has at least two words.

This is a package directive, not a PHPStan `@phpstan-ignore` directive.
Put a dot between the rule identifier and the fingerprint.
Use `@phpstan-ignore` so that this rule can check the fingerprint and
report a missing reason.

```php
// @phpstan-ignore phpstanCwe.cwe95.<fingerprint> (This code uses fixed local text.)
eval('return 1 + 1;');
```

Put the ignore comment immediately before the statement that calls `eval()`.
An ignore applies to one finding in that statement, not to other statements
with the same fingerprint. An ignore applies only when its fingerprint matches
that finding. The rule
reports an unmatched or stale fingerprint. It also reports an ignore with an
invalid fingerprint or a reason with fewer than two words.

## Configuration

Use the PHP configuration to check PHP request superglobals:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/config/cwe95.neon
```

Use the Laravel configuration to also check Laravel request input:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/config/cwe95-laravel.neon
```

`phpstanCwe.minProbability` defaults to `0`. Set it from `0` to `100` to
filter lower scores.

## Scope and known limitations

- The rule checks `eval()` only. It does not check templates, shell commands,
  string assertions, or other code execution functions.
- The rule follows local assignments in source order. It does not merge
  branches, repeat loops, or follow values between functions.
- Local assignments stay within their function, closure, or arrow function.
  The rule does not follow captured values into a closure or arrow function.
- The rule does not detect every external input source or transformation.
- A value that the rule does not identify as request input may still be
  controlled by an external user.
- The fingerprint uses the file path and function or method name. A file
  rename or a relevant code or source change needs a new review.
- Two identical `eval()` expressions in the same scope with the same sources
  can have the same fingerprint.
- Earlier rule versions did not keep closure assignments separate. Replace
  old closure fingerprints after you review the updated findings.

Full explanation: https://cwe.mitre.org/data/definitions/95.html
