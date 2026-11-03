# Shared Laravel request input detection

`LaravelRequestInput` identifies Laravel request input for the
[CWE-78 command rule](Rules/Cwe78/Cwe78Rule.md), the
[CWE-79 HTML rule](Rules/Cwe79/Cwe79Rule.md), the
[CWE-89 database rule](Rules/Cwe89/Cwe89Rule.md), and the
[CWE-89 Laravel SQL rule](Rules/Cwe89/Cwe89LaravelRule.md).
It checks input sources only. Each rule selects the command, output, or
SQL expressions to check, applies its own protections, and creates reports.

## Configuration

The package's `extension.neon` enables Laravel input checks for all these
rules. To enable one rule, use its public configuration:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/cwe78-laravel.neon
```

For only the HTML rule:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/cwe79.neon
```

For SQL checks, use `cwe89.neon` for PDO and mysqli, or
`cwe89-laravel.neon` for Laravel raw SQL. Both detect the shared Laravel
request sources. Bound values do not become SQL text.

`cwe78.neon` enables command checks without Laravel input detection.
Do not include it with `cwe78-laravel.neon`. The Laravel command variant
uses the base command rule and does not add duplicate command reports.

Laravel is not a package dependency. PHPStan must know the
`Illuminate\Http\Request` class and its subclasses to identify typed
request objects. This includes form request classes.
PHPStan must also resolve the global `request()` helper.

## Request sources

The shared detector checks these sources:

- The global `request('key')` helper, including named arguments.
- `request()->input('key')` and other supported input methods.
- Input methods on an `Illuminate\Http\Request` instance or subclass.
- Property and array reads on a request object, such as `$request->file`
  and `$request['file']`.

The supported methods are `input`, `get`, `query`, `post`, `cookie`,
`header`, `server`, `all`, `only`, `except`, `json`, `collect`, `string`,
`str`, `route`, `validated`, `safe`, `bearerToken`, and `getContent`.
Validation and string conversion do not escape shell arguments or HTML.
Other methods, such as `method()` and `path()`, are not classified as
input sources. Nullsafe input reads are supported.

## Context-specific protections

The shared detector does not decide whether a value is safe. Each rule
checks the protections for its own use of the input.

Unsafe command example:

```php
use Illuminate\Http\Request;

function convertFile(Request $request): void
{
    exec('convert ' . $request->input('file') . ' /tmp/output.png');
}
```

Protected argument example:

```php
exec('convert ' . escapeshellarg(request('file')) . ' /tmp/output.png');
```

The protected command still gets a low review report.
`escapeshellarg()` protects one shell argument. It does not make an
untrusted executable name safe, and it does not protect HTML output.

Unsafe HTML example:

```php
echo request('name');
```

Protected HTML example:

```php
echo htmlspecialchars(request('name'));
```

The HTML rule accepts its supported HTML escape calls and numeric casts.
HTML escaping does not protect a shell command. See each rule document
for its exact escape checks and output limits.

For SQL, bind request values instead of adding them to query text:

```php
DB::select('SELECT * FROM users WHERE name = ?', [request('name')]);
```

HTML and shell escape calls do not protect SQL. The database rule accepts
numeric casts. The Laravel SQL rule keeps its own checks for identifier
wrapping and bindings.

## Ratings and ignores

The shared detector does not assign severity or probability.
The command rule uses `phpstanCwe.cwe78` and its context-based ratings.
The HTML rule uses `phpstanCwe.cwe79`, high severity, and a probability
score of 80.
Both SQL rules use `phpstanCwe.cwe89` and high severity. Known request
input gets a probability score of 80. The Laravel SQL rule also reports
unknown dynamic sources with a score of 45.
Severity describes possible harm. Probability estimates confidence in
the finding. It is not a measured probability of an attack.

Set `phpstanCwe.minProbability` to filter these reports. The default is
`0`. Use the rule's error identifier for an inline PHPStan ignore.
CWE-78 ignores must give a reason with at least two words.

## Known limits

- The detector identifies sources in the current expression. It does not
  trace assignments or follow input across functions, branches, or loops.
  The command and Laravel SQL rules add simple local assignment tracking.
  The HTML and direct database rules do not follow assigned values.
- It does not identify a request object from its variable name alone.
- It does not inspect request facades or custom input methods.
- A different function called `request()` is not a request source.
- An unrecognised source does not prove that a value is safe.
- Each rule has more limits. See its rule document.

Full CWE explanations:

- OS command injection: https://cwe.mitre.org/data/definitions/78.html
- Cross-site scripting: https://cwe.mitre.org/data/definitions/79.html
- SQL injection: https://cwe.mitre.org/data/definitions/89.html
