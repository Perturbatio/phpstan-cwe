# PHPStan CWE rules

[![PHP Composer](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml/badge.svg)](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml)

PHPStan CWE is a PHPStan extension that finds *possible* security weaknesses in PHP code. It reports the severity, confidence score, and related CWE reference for each finding. It also checks Laravel routes for critical operations that may lack authentication.

The package will work for any PHP project that uses PHPStan 2.x. It has been tested with Laravel 10.x and 11.x, but it does not require Laravel.

However, there are some Laravel only rule implementations.

---

This package reports potential web application weaknesses during PHPStan
analysis. 

The PHP rules check request input at HTML and SQL sinks.

The CWE-78 rule reports command execution calls for review, follows simple local assignments, and ranks direct request input by severity and probability.

Its Laravel variant also checks the `request()` helper and input reads from `Illuminate\Http\Request` objects and their subclasses.

The CWE-79 HTML rule checks the same Laravel request sources. It also follows simple local assignments, concatenation, `.=` assignments, interpolation, and input passed to text calls. HTML escape calls and numeric casts stop this tracking. 

Both rules
use one shared source detector, but keep separate escape checks for shell
arguments and HTML output. 

Laravel HTML checks are enabled in `config/cwe79.neon`
and `extension.neon`.

Both CWE-89 rules also use this shared detector for Laravel request sources.

They keep their SQL-specific checks for query text and bound values.

The Laravel SQL rule checks dynamic values in raw Eloquent and Query Builder expressions and `DB::select()`. It follows simple local assignments. 

It also reports dynamic values with an unknown source at a lower probability score.

The Blade rule checks raw output tags in templates. The PHP rules do not
trace values across function calls or merge execution paths. The direct
database rule does not follow local assignments. The Laravel SQL rule reports
dynamic values without deciding whether their source is safe. Use other
security checks and code review with these rules.

> [!NOTE]
> This package cannot cater for all possible ways a CWE can be exploited,
> but it does provide some useful checks.

## Installation

Install the package with Composer:

[//]: # (TODO: Add a version constraint when the first release is tagged.)
```sh
composer require --dev perturbatio/phpstan-cwe
```

Add the configuration file to your `phpstan.neon`:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon
```

The default file enables all rules. Configure critical operations for CWE-306
as shown below. To use one rule,
include the specific rule, e.g. `config/cwe78.neon`, `config/cwe78-laravel.neon`,
`config/cwe79.neon`, `config/cwe79-blade.neon`, `config/cwe89.neon`, or
`config/cwe89-laravel.neon`, or `config/cwe306-laravel.neon` instead of
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

## Laravel authentication checks

The experimental [CWE-306 Laravel rule](src/Rules/Cwe306/Cwe306LaravelRule.md)
checks routes that reach functions or methods which you configure as requiring
authentication. It checks supported middleware, controller calls, and custom
form request authorization. Unknown controls lower confidence; they do not
prove that authentication is absent.

The full extension enables this rule. To use it alone, include
`config/cwe306-laravel.neon`. Set
`phpstanCwe.cwe306CriticalOperations`. The default list is empty. 

The list
accepts exact function or `Class::method` names and wildcard `Class::method`
patterns. Use `*` within an identifier and `**` for zero or more namespace
segments. Prefix an inclusion pattern
with `!` to exclude it. Exclusions override exact names and inclusion patterns,
regardless of list order.

If the rule is enabled with an empty list, it reports one configuration error
with identifier `phpstanCwe.cwe306Configuration`. This error is not a vulnerability
finding and is not filtered by `minProbability`.

Do not include the rule again when you use `extension.neon`. See the rule document for
middleware configuration, supported syntax, and known limitations.

### Example project configuration

See the [standard Laravel project example](src/Rules/Cwe306/Cwe306LaravelRule.md#standard-laravel-project-example)
for a configuration with Larastan, model and builder deletes, and common
action and service patterns.

For example, require authentication before a caller deletes a user or calls an
account deletion action. Add this to your project's `phpstan.neon`:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon

parameters:
    paths:
        - app
        - routes
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Models\User::delete
            - App\Actions\DeleteAccount::__invoke
            - App\Services\*::delete
            - App\Models\**\*::delete
            - '!App\Models\Legacy\**\*::delete'
        minProbability: 0
```

The wildcard in `App\Services\*::delete` matches calls to `delete` on a class
directly in `App\Services`. It does not match classes in child namespaces. To
match calls to all methods on those classes, use `App\Services\*::*`.
Use `App\Models\**\*::delete` to include classes directly in `App\Models` and
in all its child namespaces. Use `*Controller::delete*` to match part of a
class or method name.

| Syntax | Meaning |
|--------|---------|
| `*` | Zero or more characters within one identifier |
| `**` | Zero or more complete namespace segments, before the final class segment |
| Leading `!` | Exclude matching operations |

Identifiers must remain valid and non-empty. For example, `*Controller` matches
`Controller`, and `delete*` matches `delete` and `deleteAccount`.
`App\Models\*::delete` does not match `App\Models\Admin\User::delete`;
`App\Models\**\*::delete` does. Neither matches `App\ModelsExtra\User::delete`
or a method named `forceDelete`.

A pattern must include `Class::method`. Embedded or adjacent `**`, a final
class or method segment of `**`, runs of three stars, `?`, character ranges,
brace expansion, and wildcard function names are not supported.

Patterns only match symbols that the scanner resolves. They do not enumerate
classes or add support for dynamic method names. These are PHP namespace patterns,
not directory patterns. The model pattern does not prove Eloquent inheritance
or resolve an unknown return type. Chained calls can match the actual
receiver operation when PHPStan establishes its type.

For chained Eloquent or Query Builder deletes, configure
`Illuminate\Database\Eloquent\Builder::delete` or
`Illuminate\Database\Query\Builder::delete`, not only a model pattern.
Dynamic Eloquent chains can require Larastan in the analysed application.
See [chained method calls](src/Rules/Cwe306/Cwe306LaravelRule.md#chained-method-calls)
for configuration, tested dependencies, and confidence limits.

An exclusion pattern starts with `!`. It overrides matching exact names and
inclusion patterns even when it appears first in the list. For example,
`!App\Models\Legacy\**\*::delete` excludes `delete` methods on classes directly
inside `App\Models\Legacy` and in its child namespaces. The rule checks both the runtime class and the
declaring class for an inherited method. An exclusion that matches either
operation identity takes priority.

Analyse the route, controller, model, action, and form request files together.
The minimum score applies to all enabled CWE rules. This example leaves global
middleware unknown. Set `cwe306GlobalMiddleware: []` only after you confirm that
no global middleware requires authentication.

> [!WARNING]
> The rule does not read Laravel's effective global middleware configuration.
> Leave `cwe306GlobalMiddleware` unknown unless you have checked that
> configuration. An incorrect empty list can overstate confidence in a finding.

The rule reports these routes because they reach a configured operation without
a supported authentication check:

```php
use App\Actions\DeleteAccount;
use App\Models\User;
use Illuminate\Support\Facades\Route;

Route::delete('/users/{user}', function (User $user): void {
    $user->delete();
});

Route::post('/accounts/delete', function (DeleteAccount $action): void {
    $action->__invoke();
});
```

`User::delete` identifies calls on a typed `User` receiver, including an inherited
Eloquent `delete()` method. It does not identify every Eloquent deletion. Calls
such as `User::find($id)->delete()` and `User::where(...)->delete()` use receivers
that this rule does not resolve.

The action example uses an explicit `__invoke()` call. The rule does not resolve
`$action()` or container calls such as `app(DeleteAccount::class)()`. For a service,
configure its full method name, such as
`App\Services\AccountService::deleteAccount`, and call that method on a typed
service parameter.

Direct local container assignments are also supported:

```php
$action = app(DeleteAccount::class);
$action->__invoke();

$action = app()->make(DeleteAccount::class);
$action->__invoke();
```

The class argument must use a literal `Class::class`. The rule checks an exact
configured method on the requested class at lower confidence. It does not read
container bindings or follow the requested class body. A binding can return a
different class, so these assignments cannot establish authentication.
Dynamic class arguments, other container methods, and direct `$action()` calls
remain unsupported.

To require authentication for both routes, put them in an authenticated group:

```php
Route::middleware('auth:sanctum')->group(function () {
    Route::delete('/users/{user}', function (User $user): void {
        $user->delete();
    });

    Route::post('/accounts/delete', function (DeleteAccount $action): void {
        $action->__invoke();
    });
});
```

For a controller group, add the action to the critical operation list only if
the application requires authentication for that action:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Http\Controllers\Api\V1\ProductController::store
```

```php
use App\Http\Controllers\Api\V1\ProductController;

Route::controller(ProductController::class)->group(function (): void {
    Route::post('/products', 'store'); // Report: No supported authentication control.
});

Route::controller(ProductController::class)->middleware('auth:sanctum')->group(function (): void {
    Route::post('/products', 'store'); // No report: Authentication is required.
});
```

Authentication does not prove permission to create a particular product.

> [!WARNING]
> CWE-306 checks **authentication**, not permission to delete a specific record.
> Keep the policy or other authorization check that your application requires.
> Route model binding alone does not authenticate the caller.

Run the analysis from your project directory:

```sh
vendor/bin/phpstan analyse --configuration=phpstan.neon
```

The identifier is `phpstanCwe.cwe306`. An inline ignore must give a reason
with at least two words:

```php
// @phpstan-ignore phpstanCwe.cwe306 (External gateway authenticates callers)
Route::post('/accounts/delete', [AccountController::class, 'destroy']);
```

A missing or short reason produces a non-ignorable
`phpstanCwe.ignoreReason` error.

> [!WARNING]
> The reason check applies only to identifier-specific inline ignore annotations. 
> Baselines, global `ignoreErrors`, and identifier-free line ignores can suppress 
> findings without a reason. Review these settings separately.

### Important detection limitations

> [!WARNING]
> **Route coverage is incomplete.** The rule does not expand resource routes,
> route macros, dynamic route handlers, or controller groups with dynamic
> controllers or non-closure registration callbacks. Adding `routes/`
> to the analysed paths does not mean that every Laravel route is checked.
> Review unsupported routes separately.

> [!WARNING]
> **Validation does not prove authentication.** `web`, `api`, CSRF checks, and
> form request validation do not establish that the caller is authenticated.
> 
> e.g. A form request that returns `true` from `authorize()` does not add an
> authentication control.

> [!WARNING]
> **A redirect does not stop execution.** A supported authentication check must
> stop the guest path before the critical operation. An ignored Boolean check
> or a check after the operation does not protect it.

See the [full rule limitations](src/Rules/Cwe306/Cwe306LaravelRule.md#known-limitations)
for unsupported calls and execution paths.

## Set a minimum probability score

The default minimum is `0`. Set a value from `0` to `100` in `phpstan.neon`:

```neon
parameters:
    phpstanCwe:
        minProbability: 80
```

Scores differ by rule. The CWE-306 score depends on the available evidence.
A finding at the minimum score is kept. A finding below the minimum is
filtered. The score is an estimate of detection confidence, not a measured
probability of an attack. Severity is separate and describes possible harm.
See the rule documents for scores and severity.

> [!WARNING]
> Use `minProbability: 0` during initial setup. A higher minimum can hide real
> findings when the rule cannot resolve middleware or calls.
>
> For CWE-306, unknown global middleware can limit a finding to 60%, and unresolved 
> calls can reduce it further. A low score does not mean that an operation is safe.

Each report gives a CWE number, a reason, a severity, a probability score,
and a link to the MITRE CWE site. Reports are ignorable PHPStan errors.
The stable identifiers are `phpstanCwe.cwe78`, `phpstanCwe.cwe79`,
`phpstanCwe.cwe89`, and `phpstanCwe.cwe306`.
Both CWE-89 rules use `phpstanCwe.cwe89`. CWE-78 and CWE-306 inline ignore
comments must include a reason with at least two words. A short reason is
reported with `phpstanCwe.ignoreReason`.
The same data is in the PHPStan error metadata.

Read [CWE-78](src/Rules/Cwe78/Cwe78Rule.md), [CWE-79](src/Rules/Cwe79/Cwe79Rule.md) and
[CWE-79 in Blade](src/Rules/Cwe79/Cwe79BladeRule.md) and
[CWE-89](src/Rules/Cwe89/Cwe89Rule.md) and
[CWE-89 in Laravel query builders](src/Rules/Cwe89/Cwe89LaravelRule.md) for
examples and limitations.

## FAQ

### How do I fix an error?

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

### Why does the package not report an expected violation?

First, check that PHPStan analyses the file. Autoloading a file does not add it
to the analysed paths. For CWE-306, include both application code and routes:

```neon
parameters:
    paths:
        - app/
        - routes/
```

Run PHPStan with the configuration file that contains these paths and the
package include:

```sh
vendor/bin/phpstan analyse --configuration=phpstan.neon
```

For CWE-306, also check that the full `Class::method` name is in
`phpstanCwe.cwe306CriticalOperations`. A `minProbability` greater than the
finding's score, an ignore, or a baseline can hide a report.

The rule must also support the call syntax. It resolves a call such as
`$action->execute()` on a typed action parameter or after a direct local
`$action = new Action()` assignment. It also checks configured methods after
`$action = app(Action::class)` or `$action = app()->make(Action::class)`.
Direct chains such as `$factory->createService()->execute()` can match when
PHPStan establishes the returned object's type. Assigned factory results,
object copies, and dynamic class names are not resolved. Types changed inside branches are not
retained after the branch. See the
[CWE-306 known limitations](src/Rules/Cwe306/Cwe306LaravelRule.md#known-limitations).
No report does not prove that the code has an authentication control.

### Why does CWE-306 not recognise my authentication middleware?

`cwe306MiddlewareAliases` maps an alias to its actual middleware class. It does
not declare that the class requires authentication:

```neon
parameters:
    phpstanCwe:
        cwe306MiddlewareAliases:
            laravelAuth: Illuminate\Auth\Middleware\Authenticate
            filamentAuth: Filament\Http\Middleware\Authenticate
            customAuth: App\Http\Middleware\Authenticate
```

The rule recognises `laravelAuth` in this example. It currently accepts only
the exact class `Illuminate\Auth\Middleware\Authenticate` as an authentication
control. The built-in `auth` alias needs no configuration. Guard suffixes such
as `auth:sanctum` are supported.

The Filament and custom classes remain unknown. The rule does not inspect their
code or check their parent classes. Unknown middleware can lower confidence in
a finding; it does not prove that the route lacks authentication.

> [!WARNING]
> Map each alias to the class that your application actually uses. Do not map
> a custom or Filament alias to `Illuminate\Auth\Middleware\Authenticate` only
> to stop a finding. An incorrect mapping can hide missing authentication.

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
