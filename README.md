# PHPStan CWE rules

[![PHP Composer](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml/badge.svg)](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml)

This package reports potential web application weaknesses during PHPStan
analysis. The PHP rules check direct request input at HTML and SQL sinks.
The CWE-78 rule reports command execution calls for review, follows simple
local assignments, and ranks direct request input by severity and probability.

The Laravel SQL rule checks dynamic values in raw Eloquent and Query Builder
expressions and `DB::select()`. It follows simple local assignments. It also
reports dynamic values with an unknown source at a lower probability score.

The Blade rule checks raw output tags in templates. The PHP rules do not
trace data flow through variables or functions. The Laravel SQL rule reports
dynamic values without deciding whether their source is safe. Use other
security checks and code review with these rules.

> [!NOTE]
> This package cannot cater for all possible ways a CWE can be exploited,
> but it does provide some useful checks.

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

The default file enables all the rules. To use one rule,
include the specific rule, e.g. `cwe78.neon`, `cwe79.neon`,
`cwe79-blade.neon`, `cwe89.neon`, or `cwe89-laravel.neon` instead of
`extension.neon`.

If you want to include all rules but ignore a specific rule.
You cannot exclude a specific rule once loaded, so it will still be processed by PHPStan, but you _can_ ignore the errors it produces.

In this case, add the following to your `phpstan.neon`
```neon
parameters:
    ignoreErrors:
        -
            identifier: phpstanCwe.cwe79 # ignore CWE-79 reports
```

This is *probably* safer than only building a set of rules you want to use, 
because it will still report any new CWE rules added in future versions of this package.

And at the very least, you'll have a record of the CWE rules you have chosen to ignore, 
so you can review them later.

The Blade rule scans `resources/views` and its child directories when the
directory exists. It runs when PHPStan analyses at least one PHP file.
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
The stable identifiers are `phpstanCwe.cwe78`, `phpstanCwe.cwe79`, and
`phpstanCwe.cwe89`. Both CWE-89 rules use `phpstanCwe.cwe89`. CWE-78 ignore
comments must include a reason with at least two words. A short reason is
reported with `phpstanCwe.ignoreReason`.
The same data is in the PHPStan error metadata.

Read [CWE-78](src/Rules/Cwe78Rule.md), [CWE-79](src/Rules/Cwe79Rule.md) and
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

An example output is:

```text
 ------ ----------------------------------------------------------------------
  Line   tests/fixtures/CWE-89/laravel.php
 ------ ----------------------------------------------------------------------
  133    CWE-89: Request input is used in Laravel raw SQL. Use a bound parameter. Severity: high. Probability: 80%.      
         https://cwe.mitre.org/data/definitions/89.html                                                                  
         🪪  phpstanCwe.cwe89                                                                                            
         at tests/fixtures/CWE-89/laravel.php:133                                                                        
  135    CWE-89: Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter. Severity:  
         high. Probability: 45%. https://cwe.mitre.org/data/definitions/89.html                                          
         🪪  phpstanCwe.cwe89      
 ------ ----------------------------------------------------------------------

 ------ ----------------------------------------------------------------------
  Line   app/services/UpdateProfile.php                                                                                                                                                           
 ------ ----------------------------------------------------------------------
  80     CWE-89: Warning: The source of a dynamic value in Laravel raw SQL
         is unknown.
         Use a bound parameter. Severity: high. Probability: 45%. 
         https://cwe.mitre.org/data/definitions/89.html  
         🪪  phpstanCwe.cwe89                                                                                                                                                                   
         at app/services/UpdateProfile.php:80                                                                                                                                                          
 ------ -----------------------------------------------------------------------
```

The project uses `phpstan.neon.dist` to set level 10 and analyse `src`.
This project config is not included by the package's rule configuration files.

## Run tests

Tests in `tests/Unit` check the scanner and report data. Tests in
`tests/Integration` run rules with PHPStan. Rule fixtures are in
`tests/fixtures/CWE-78`, `tests/fixtures/CWE-79`, and
`tests/fixtures/CWE-89`. The fixture used by multiple rules is in
`tests/fixtures/shared`.

```sh
vendor/bin/pest
vendor/bin/pest --testsuite Unit
vendor/bin/pest --testsuite Integration
```

GitHub Actions runs tests in parallel. It requires 100% code coverage and a
100% mutation score. Both checks use PCOV for coverage and disable test
impact analysis to run the full test suite.
The mutation check also fails if a test reports a PHP warning.

Run the same checks with:

```sh
composer test:coverage:check -- --no-tia --parallel
composer test:mutation:check -- --no-tia --parallel
```

## How do I fix an error?

Example error:

```text
CWE-89: Unprotected dynamic value in raw SQL expression. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html
```
Example code that causes the error:
```PHP
DB::select("SELECT * FROM users WHERE username = '$user' AND password = '$password'");
```
Fix:
```PHP
DB::select(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [$user, $password],
);
```

selectRaw example:

Example code that causes the error:
```PHP
$query->selectRaw("DATE_FORMAT(created_at, '{$format}') as {$alias}")
```

Fix:
```PHP
$query->selectRaw("DATE_FORMAT(created_at, '?') as ?", [$format, $alias]);
```