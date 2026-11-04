# PHPStan CWE rules

[![PHP Composer](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml/badge.svg)](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml)

This package reports potential web application weaknesses during PHPStan
analysis. The PHP rules check request input at HTML and SQL sinks.
The CWE-78 rule reports command execution calls for review, follows simple
local assignments, and ranks direct request input by severity and probability.
Its Laravel variant also checks the `request()` helper and input reads
from `Illuminate\Http\Request` objects and their subclasses.
The CWE-79 HTML rule checks the same Laravel request sources. It also follows
simple local assignments, concatenation, `.=` assignments, interpolation,
and input passed to text calls. HTML escape calls and numeric casts stop
this tracking. Both rules
use one shared source detector, but keep separate escape checks for shell
arguments and HTML output. Laravel HTML checks are enabled in `config/cwe79.neon`
and `extension.neon`.
Both CWE-89 rules also use this shared detector for Laravel request sources.
They keep their SQL-specific checks for query text and bound values.

The Laravel SQL rule checks dynamic values in raw Eloquent and Query Builder
expressions and `DB::select()`. It follows simple local assignments. It also
reports dynamic values with an unknown source at a lower probability score.

The Blade rule checks raw output tags in templates. The PHP rules do not
trace values across function calls or merge execution paths. The direct
database rule does not follow local assignments. The Laravel SQL rule reports
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
include the specific rule, e.g. `config/cwe78.neon`, `config/cwe78-laravel.neon`,
`config/cwe79.neon`, `config/cwe79-blade.neon`, `config/cwe89.neon`, or
`config/cwe89-laravel.neon` instead of
`extension.neon`.

For example, to enable only the PHP HTML rule:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/config/cwe79.neon
```

Rule configuration files are grouped as follows:

| Path | Purpose |
|------|---------|
| `extension.neon` | Main entry point. Enables all rules. |
| `config/cwe*.neon` | Public entry points for individual rules. |
| `config/parameters.neon` | Shared defaults and parameter schema. |
| `config/rules/` | Internal rule and collector service definitions. |

The individual rule files are located in `config/`.

The full extension uses the Laravel CWE-78 variant. Use `config/cwe78.neon`
for only the base command checks, or `config/cwe78-laravel.neon` to add Laravel
request sources. Do not include both files. Both use `phpstanCwe.cwe78`
and report each command only once. See the
[shared Laravel input document](src/LaravelRequestInput.md)
for supported request methods, ratings, and limitations.

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
[Blade rule document](src/Rules/Cwe79/Cwe79BladeRule.md) for the exact placement.

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

Read [CWE-78](src/Rules/Cwe78/Cwe78Rule.md), [CWE-79](src/Rules/Cwe79/Cwe79Rule.md) and
[CWE-79 in Blade](src/Rules/Cwe79/Cwe79BladeRule.md) and
[CWE-89](src/Rules/Cwe89/Cwe89Rule.md) and
[CWE-89 in Laravel query builders](src/Rules/Cwe89/Cwe89LaravelRule.md) for
examples and limitations.

## IDE support

PHPStan stores its classes in a PHAR archive. If your IDE cannot find these
classes, use [`stubs/phpstan.php`](stubs/phpstan.php). This file declares the
PHPStan 2.x classes and methods used by this package. It does not contain
their implementations or the full PHPStan API.

In PhpStorm, keep `stubs/` in the project and do not mark it as excluded.
For another project, add this directory under **Settings > PHP > Include Path**.
In other IDEs, add this directory to the PHP language server's include paths.
Do not index both the stub file and the PHPStan PHAR source. This can cause
duplicate class warnings.

Do not require this file, add it to Composer autoload settings, or add it to
PHPStan's `stubFiles`, `scanFiles`, or analysis paths. It is for IDE indexing
only. Runtime code must use the installed PHPStan classes.

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

## Run local checks

Run the local checks from the package root:

```sh
./check
```

The script runs `format:check`, `analyse`, `test`, and
`test:mutation:check`, in that order. It stops at the first failed command
and returns that command's exit code. Composer's process timeout is disabled.
Both test commands use `--no-tia --parallel`. The mutation command also uses
`--no-cache`. Its Composer script requires a 100% score and fails on warnings.

Select checks by name. Put extra test arguments after `--`:

```sh
./check analyse test
./check -- --processes=16
```

Extra arguments go to test commands only. With Pest 5.3.5, use `--processes`
for mutation tests only after you apply the Pest fix that removes this option
from mutation subprocess arguments. Without this fix, subprocess option errors
can count as detected mutations. The default command does not set a worker count.

Use `./check --help` to show the command syntax.

### Local settings

Copy the example file to set local defaults:

```sh
cp .check.local.example .check.local
```

Git ignores `.check.local`. The script reads it from the package root when it
exists. Without this file, the defaults above apply. The file uses Bash syntax
and is executed by `./check`. Use only a file that you trust.

The example file lists all settings:

| Setting | Default | Purpose |
|---------|---------|---------|
| `CHECK_SCRIPTS` | `(format:check analyse test test:mutation:check)` | Script names in execution order. |
| `CHECK_PARALLEL` | `true` | Add `--parallel` to test commands. |
| `CHECK_PROCESSES` | Empty | Set a positive worker count. Requires parallel tests. |
| `CHECK_NO_TIA` | `true` | Add `--no-tia` to test commands. |
| `CHECK_MUTATION_NO_CACHE` | `true` | Add `--no-cache` to mutation tests. |

Boolean settings accept only `true` or `false`. For example, set
`CHECK_PROCESSES=16` to use 16 workers with the Pest fix described above.
Command-line script names replace `CHECK_SCRIPTS`. Arguments after `--`
are added after the configured test arguments.

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

Or ensure the alias is wrapped and the type of the value is declared as a string:
```PHP
function getFormattedDate(Builder $query, string $format = '%Y%m%d', string $alias = 'formatted_date'): Builder
{
    $alias = $query->getQuery()->getGrammar()->wrap($alias);
    $query->selectRaw("DATE_FORMAT(created_at, ?) as {$alias}", [$format]);
}
```