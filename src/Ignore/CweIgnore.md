# Package ignores with fingerprints

All rules in this package (CWE-78, CWE-79 in PHP and Blade, CWE-89, CWE-95, and
CWE-306) support the `@phpstan-ignore` comment. Use it to suppress one
finding after you check that the code is safe.

Put a dot between the rule identifier and the fingerprint. The package checks
this identifier. PHPStan still handles comments that use a plain rule identifier
in PHP code.

## Syntax

```php
// @phpstan-ignore phpstanCwe.cwe78.<fingerprint> (Fixed command text.)
shell_exec($command);
```

- `cweNN` is the CWE number of the rule: `cwe78`, `cwe79`, `cwe89`, `cwe95`,
  or `cwe306`.
- `<fingerprint>` is the 64-character hash from the report tip. Copy it from
  the tip. A fingerprint is lower-case hexadecimal.
- The reason in parentheses must have at least two words.

An ignore for one CWE does not suppress a finding of another CWE.

## Where to put the comment

- PHP rules: put the comment immediately before the statement that has the
  finding. If the statement is a compound statement, the ignore covers the
  findings that are inside it, but each ignore suppresses only one finding.
- CWE-306: put the comment before the route statement. The route is the
  attached statement.
- Blade: put the comment `{{-- @phpstan-ignore phpstanCwe.cwe79.<fingerprint> (<reason>) --}}`
  on the same line as the raw echo `{!! ... !!}`, or on the line before it.

## What the rule reports

| Case | Identifier |
| --- | --- |
| The hash is missing or malformed | `phpstanCwe.ignoreFingerprint` |
| The reason has fewer than two words | `phpstanCwe.ignoreReason` |
| No finding uses the ignore (a stale ignore) | `phpstanCwe.ignoreUnmatched` |

An ignore with an invalid hash or reason does not suppress the finding.
Duplicate statements that have the same fingerprint need one ignore for each
finding. A finding that is below the configured minimum probability still uses
its ignore, so the ignore is not stale.

## What the fingerprint uses

A fingerprint is a SHA-256 hash. It uses the rule, the full file path, and the
identity of the finding. It does not use comments, line numbers, token
positions, or runtime object identities. A blank line or a comment does not
change it.

| Rule | Identity |
| --- | --- |
| CWE-78 | Function or method name, sink expression, and the detected facts (request input, fixed text, assignment) |
| CWE-79 PHP | Function or method name and printed expression |
| CWE-79 Blade | Normalised raw echo expression |
| CWE-89 | Function or method name, sink expression, and the kind (direct or Laravel). Laravel findings also use the status of the value |
| CWE-95 | Function or method name, closure position, `eval()` expression, and input sources |
| CWE-306 | Route method and arguments (not the handler), handler, and critical operation |

## Limitations

- The hash uses the full file path. A moved or renamed file gets new
  fingerprints. Review its ignores again.
- A change to the checked expression or to the detected facts creates a new
  fingerprint. The old ignore is then reported as stale.
- A closure is part of the identity only where the rule documents it (CWE-95).
- In PHP, the package does not check the reason of a native ignore. Native
  PHPStan ignores, baselines, and `ignoreErrors` can still hide a finding
  without a fingerprint or a reason.
- In Blade, a comment for `phpstanCwe.cwe79` without a fingerprint reports
  `phpstanCwe.ignoreFingerprint` and does not hide a finding.
