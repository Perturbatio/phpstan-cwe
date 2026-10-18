# PHPStan CWE rules

This package reports potential web application weaknesses during PHPStan
analysis. The PHP rules check direct request input at HTML and SQL sinks.
The Laravel SQL rule checks dynamic values in raw Eloquent and Query Builder
expressions and `DB::select()`. It follows simple local assignments. It also
reports dynamic values with an unknown source at a lower probability score.
The Blade rule checks raw output tags in templates. The PHP rules do not
trace data flow through variables or functions. The Laravel SQL rule reports
dynamic values without deciding whether their source is safe. Use other
security checks and code review with these rules.

## Install

Install the package with Composer:

```sh
composer require --dev perturbatio/phpstan-cwe
```

Add the configuration file to your `phpstan.neon`:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon
```

The default file enables the PHP rules and the Blade rule. To use one rule,
include `cwe79.neon`, `cwe79-blade.neon`, `cwe89.neon`, or
`cwe89-laravel.neon` instead of `extension.neon`.

The Blade rule scans `resources/views` and its child directories when the
directory exists. It runs when PHPStan analyzes at least one PHP file.
Set other directories in `phpstan.neon` if necessary:

```neon
parameters:
    phpstanCwe:
        bladeDirectories:
            - resources/views
            - packages/shop/resources/views
```

Relative paths start at the current working directory. Set the list to
`[]` to stop the Blade scan.

To ignore one Blade raw echo, put a Blade comment immediately before it:

```blade
{{-- @phpstan-ignore phpstanCwe.cwe79 (This value is trusted.) --}}
{!! $trustedHtml !!}
```

An ignore with no matching raw echo gets a report. See the
[Blade rule document](src/Rules/Cwe79BladeRule.md) for the exact placement.

## Set a minimum probability score

The default minimum is `0`. Set a value from `0` to `100` in `phpstan.neon`:

```neon
parameters:
    phpstanCwe:
        minProbability: 80
```

Each rule has a probability score of `80`. Setting a minimum higher than
this stops all rules from reporting. This score is an estimate of detection
confidence. It is not a measured probability of an attack. Severity is
separate: each initial rule reports **high** severity because the possible
harm is high.

Each report gives a CWE number, a reason, a severity, a probability score,
and a link to the MITRE CWE site. Reports are ignorable PHPStan errors.
The stable identifiers are `phpstanCwe.cwe79` and `phpstanCwe.cwe89`.
Both CWE-89 rules use `phpstanCwe.cwe89`.
The same data is in the PHPStan error metadata.

Read [CWE-79](src/Rules/Cwe79Rule.md) and
[CWE-79 in Blade](src/Rules/Cwe79BladeRule.md) and
[CWE-89](src/Rules/Cwe89Rule.md) and
[CWE-89 in Laravel query builders](src/Rules/Cwe89LaravelRule.md) for
examples and limits.

## Check code style

Laravel Pint uses the PSR-12 preset. Check PHP files with:

```sh
composer format:check
```

Fix style issues with:

```sh
composer format
```

Run PHPStan analysis with:

```sh
composer analyse
```

## Run tests

Tests in `tests/Unit` check the scanner and report data. Tests in
`tests/Integration` run rules with PHPStan. Rule fixtures are in
`tests/fixtures/CWE-79` and `tests/fixtures/CWE-89`. The fixture used by
both rules is in `tests/fixtures/shared`.

```sh
vendor/bin/pest
vendor/bin/pest --testsuite Unit
vendor/bin/pest --testsuite Integration
```
