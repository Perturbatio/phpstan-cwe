# CWE-306: Missing authentication for critical function in Laravel

This rule checks Laravel HTTP routes that call a configured critical
function or method. A critical operation is an operation that your application
requires a caller to authenticate before it runs. The rule does not assume that
all database writes or all POST routes require authentication.

The rule uses PHP syntax trees. It does not start the application or run Artisan.
Laravel is not a package dependency. The supported syntax includes route closures,
arrow functions, controller actions, and invokable controllers.

See the [controller group design](Cwe306LaravelRule.future-plans.md) for
the implementation plan.

## Configuration

Include the individual configuration instead of `extension.neon`:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/config/cwe306-laravel.neon

parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Services\AccountService::deleteAccount
            - App\Services\AccountService::exportPrivateData
        cwe306MiddlewareAliases:
            members: Illuminate\Auth\Middleware\Authenticate
```

The critical operation list is empty by default. Names are full function names
or `Class::method` names. It also accepts wildcard `Class::method` patterns.
Name comparison is not case-sensitive. Do not list a valid public operation,
such as a contact form submission.

Use `*` within an identifier and `**` for recursive namespace matching:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Services\*::delete
            - App\Actions\Data\DeleteRecords\*::*
            - App\Models\**\*::delete
            - App\Http\**\*Controller::delete*
            - '!App\Models\Legacy\**\*::delete'
```

`App\Services\*::delete` matches calls to `delete` on classes directly in
`App\Services`. It does not match classes in child namespaces. `*::*` matches
calls to all methods on those direct child classes.

| Syntax | Meaning |
|--------|---------|
| `*` | Zero or more characters within one identifier |
| `**` | Zero or more complete namespace segments, before the final class segment |
| Leading `!` | Exclude matching operations |

The matched identifiers must be valid and non-empty. `*Controller` matches
`Controller` and `UserController`. `delete*` matches `delete` and
`deleteAccount`. A partial star cannot cross `\` or `::`.

`App\Models\**\*::delete` matches `App\Models\User::delete` and
`App\Models\Admin\Audit\User::delete`. It does not match
`App\ModelsExtra\User::delete`, `forceDelete`, or `deleteQuietly`.
`**` includes zero namespace segments. It must be a complete namespace
segment, not part of an identifier or the final class or method segment.
Adjacent `**` segments, runs of three stars, `?`, character ranges, brace
expansion, and wildcard function names are not supported.

A wildcard entry must use `Class::method` syntax. Patterns only
match symbols that the scanner resolves. They do not enumerate classes or add
support for dynamic calls. They match PHP symbols, not directory paths.
The model pattern does not establish Eloquent inheritance or add support for
unresolved chains such as `User::find($id)->delete()`.

Prefix an inclusion pattern with `!` to exclude its matches. Exclusions take
priority over matching exact names and inclusion patterns, regardless of list
order. For an inherited method, the rule checks both the runtime class and the
class that declares the method. An exclusion that matches either identity
blocks the operation.

If the list is empty, the rule reports one configuration error per analysis:
`phpstanCwe.cwe306Configuration`. It does not scan for critical operations until
you configure at least one exact operation or inclusion pattern. Exclusion
patterns alone do not enable detection. This error is not a vulnerability
finding. The `minProbability` setting does not filter it.

The full extension already enables this rule. Include only `extension.neon`
when you use all rules. Do not also include the individual configuration or
the rule service file: PHPStan rejects duplicate includes.

PHPStan must analyse the route files, controller files, form request files, and
service files together. Bodies in files outside the analysis are unknown.
Include these files in your PHPStan `paths`.

The rule does not read `bootstrap/app.php`, the HTTP kernel, or cached routes to
build the effective global middleware list. By default,
`cwe306GlobalMiddleware` is `null`, which means unknown. You can supply the
effective global middleware list from your application configuration:

```neon
parameters:
    phpstanCwe:
        cwe306GlobalMiddleware: []
```

Use `[]` only if no global middleware can require authentication. Do not use it
to omit middleware that you have not checked. An unrecognised middleware class
or alias remains unknown. Alias configuration must match the application.
The `auth` alias means Laravel's `Illuminate\Auth\Middleware\Authenticate`
unless your alias configuration replaces it. Guard names, such as `auth:sanctum`,
are supported.

> [!WARNING]
> Map each alias to its actual middleware class. This setting does not declare
> that a custom class requires authentication. The rule currently recognises
> only `Illuminate\Auth\Middleware\Authenticate`; custom classes and subclasses
> remain unknown. Do not map a custom or Filament alias to Laravel's class only
> to stop a finding. An incorrect mapping can hide missing authentication.

### Standard Laravel project example

Use this as a starting point for `phpstan.neon`. It enables all package rules
and selects common delete operations for CWE-306. Install Larastan separately
if it is not already present.

```neon
includes:
    - vendor/larastan/larastan/extension.neon
    - vendor/perturbatio/phpstan-cwe/extension.neon

parameters:
    level: 5

    paths:
        - app
        - routes

    phpstanCwe:
        minProbability: 0

        bladeDirectories:
            - resources/views

        cwe306CriticalOperations:
            # Direct model operations.
            - App\Models\**\*::delete
            - App\Models\**\*::forceDelete
            - App\Models\**\*::destroy
            - App\Models\**\*::forceDestroy

            # Chained builder operations.
            - Illuminate\Database\Eloquent\Builder::delete
            - Illuminate\Database\Eloquent\Builder::forceDelete
            - Illuminate\Database\Query\Builder::delete
            - Illuminate\Database\Query\Builder::truncate

            # Common application method names.
            - App\Actions\**\Delete*::execute
            - App\Actions\**\Delete*::__invoke
            - App\Actions\**\Prune*::execute
            - App\Services\**\*::delete*
            - App\Services\**\*::forceDelete*

        cwe306MiddlewareAliases:
            auth: Illuminate\Auth\Middleware\Authenticate

        # Keep unknown until you check the effective global middleware.
        cwe306GlobalMiddleware: null
```

Adjust the operation patterns to your application. Public operations can be
valid, and methods with other names need explicit entries. Patterns select
resolved calls; they do not guarantee full Laravel coverage. A model pattern
does not select builder operations. See [chained method calls](#chained-method-calls)
for receiver type requirements and confidence limits.

Set `cwe306GlobalMiddleware: []` only after you confirm that no global
middleware requires authentication. The standard `auth` and `auth:sanctum`
route middleware are already recognised.

## Examples

Unsafe route:

```php
use App\Services\AccountService;
use Illuminate\Support\Facades\Route;

Route::post('/accounts/delete', function (AccountService $service): void {
    $service->deleteAccount();
});
```

Protected route:

```php
Route::post('/accounts/delete', function (AccountService $service): void {
    $service->deleteAccount();
})->middleware('auth');
```

Both examples require `App\Services\AccountService::deleteAccount` in the
critical operation list. Request input is not required for a finding.

### Controller route groups

The rule resolves literal method names in closure groups that declare a
controller:

```php
use App\Http\Controllers\Api\V1\ProductController;
use Illuminate\Support\Facades\Route;

Route::controller(ProductController::class)
    ->as('products.')
    ->prefix('products')
    ->group(function (): void {
        Route::post('/', 'store')->name('store');
    });
```

If `App\Http\Controllers\Api\V1\ProductController::store` is in the
critical operation list, this route produces a finding unless a supported
authentication control applies. For example:

```php
Route::controller(ProductController::class)
    ->middleware('auth:sanctum')
    ->group(function (): void {
        Route::post('/', 'store');
    });
```

The rule also supports a literal `controller` attribute in `Route::group()`,
nested closure groups, and explicit controller handlers. An inner controller
replaces the outer controller only in its group. Middleware and exclusions
apply to nested routes. Route exclusions do not remove global middleware.

Ordinary closure groups can also contain explicit controller and closure
handlers:

```php
Route::group(['prefix' => 'products'], function (): void {
    Route::post('/one', [ProductController::class, 'store']);
    Route::post('/two', function (): void {
        eraseAccounts();
    });
});
```

Configure each action or function that requires authentication. A method-only
string does not select a controller action outside a controller group.

Select `store` only if your application requires authentication for that
operation. Authentication does not prove permission to create a particular
product.

### Laravel container assignments

The rule also checks direct local assignments from the global `app` helper:

```php
Route::post('/accounts/delete', function (): void {
    $service = app(AccountService::class);
    $service->deleteAccount();
});

Route::post('/accounts/prune', function (): void {
    $service = app()->make(AccountService::class);
    $service->deleteAccount();
});
```

Use an imported or full class name with `::class`. Positional and named
`abstract` arguments are supported. Arguments are checked before the assigned
receiver can be used. Reassignment and branch limitations are the same as for local
construction.

The requested class can differ from the actual object because of container
bindings. The rule therefore matches only the requested class and method
against exact names and patterns. It does not resolve a declaring class,
follow the requested body, or use it to establish a user
identity or an authentication guarantee. Container calls lower confidence:
these routes score 80% with confirmed empty middleware, or 40% when middleware
is unknown.

String or dynamic class arguments, unpacked arguments, direct chained calls,
other container methods, and calls through a stored container are not supported.
A local function that replaces `app` is not accepted as Laravel's helper.

### Chained method calls

The rule uses PHPStan receiver types to select configured operations in calls
such as these:

```php
ProductIssue::where('created_at', '<', $cutoff)->delete();
ProductIssue::query()->where('created_at', '<', $cutoff)->delete();
DB::table('issues')->where('created_at', '<', $cutoff)->delete();
$factory->createService()->execute();
```

Configure the actual receiver operation:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - Illuminate\Database\Eloquent\Builder::delete
            - Illuminate\Database\Query\Builder::delete
            - App\Services\Action::execute
```

An Eloquent builder is not its model. `App\Models\**\*::delete` alone does not
select builder deletes. The rule does not automatically classify every method
named `delete` as critical. Generic model information does not create a model
operation alias.

The integration tests use Laravel 13 and PHPStan 2.3, with and without
Larastan 3.14. Plain PHPStan resolves the tested `query()->where()` and
Query Builder chains from Laravel's declared types. The tested dynamic
`Model::where()` chain requires Larastan. Install and configure a compatible
Larastan version in the analysed application when PHPStan cannot resolve a
dynamic receiver. Laravel and Larastan remain development dependencies of
this package, not installation requirements.

Only statically named calls with a supported object alternative are selected.
Mixed and unresolved receivers remain unknown. Nullable and union receivers
can identify possible operations, not certain execution. Exclusions apply to
each candidate's receiver and declaring class. An excluded union alternative
does not exclude a different operation on another alternative.

Collected types select operations only. The rule does not follow an external
method body or use its receiver type to establish authentication. Chained calls
keep confidence limited to 80% with confirmed empty middleware, or 40% when
middleware is unknown. Receiver expressions and arguments are checked before
the outer operation. Supported authentication middleware still stops findings.
Calls inside deferred callbacks are not treated as executed.

## Accepted controls

- Route middleware, static middleware groups, and nested closure groups.
- Middleware removal with `withoutMiddleware()`. Global middleware cannot be
  removed with this method.
- Literal controller constructor middleware declarations with `only()` and
  `except()`, including supported parent controllers.
- Enforced `Auth::check()`, `Auth::guest()`, `auth()->check()`, and
  `auth()->guest()` branches. A guest path must stop before the operation.
- A non-null user check on a typed Laravel request or form request.
- Injected form requests whose supported `authorize()` method requires a user,
  or always denies the request.
- Resolved helper calls that stop guest execution before they return.

A redirect alone does not stop execution. An ignored Boolean check does not
enforce authentication. Authentication checks after the operation do not
protect it. `web`, `api`, validation, CSRF checks, policies, and signed URLs
are not accepted as authentication guarantees.

Form request validation does not prove authentication. A missing `authorize()`
method or `return true` adds no control. The rule checks a supported
`prepareForValidation()` body before it applies the `authorize()` result.
Overrides of the request authorization lifecycle remain unknown.

## Severity and probability

Severity is **high** because the configured operation requires authentication.
Probability estimates confidence in the finding, not the chance of an attack.

| Evidence | Score |
|----------|-------|
| Configured critical operation reached | 20 |
| Static HTTP route identified | 20 |
| Effective middleware resolved with no authentication control | 25 |
| Supported call paths resolved with no enforced authentication check | 20 |
| Explicit global configuration and middleware resolution confirm no additional control | 15 |

Unknown evidence earns no points. No findings are made without both a route
and a configured critical operation. The score can be 40, 60, 80, or 100.
These weights are estimates and are not statistically independent.
Set `phpstanCwe.minProbability` to filter findings. The default is `0`.
An accepted authentication control stops the finding for that request path.
Different routes to the same action are checked separately.

Reports use `phpstanCwe.cwe306` and give the route file and start line.
The standard metadata contains the CWE number, severity, probability, and URL.
An unresolved control does not prove that the route is available to guests.

## Ignore one finding

Put a PHPStan ignore immediately before the route. The reason must have
at least two words:

```php
// @phpstan-ignore phpstanCwe.cwe306 (External gateway authenticates callers)
Route::post('/accounts/delete', [AccountController::class, 'destroy']);
```

A missing reason, punctuation alone, or a one-word reason produces a
non-ignorable `phpstanCwe.ignoreReason` error. A reason is checked even when
the minimum score filters the CWE finding.

This check applies to identifier-specific inline ignores. PHPStan's global
`ignoreErrors`, baselines, and identifier-free line ignores are separate
suppression mechanisms. They do not have a reason field that this rule can
enforce. Use the form above to record a reason.

## Known limitations

- This is a first implementation. It does not cover plain PHP scripts.
- It does not expand resource routes, route macros, route files loaded by
  `require`, dynamic route handlers, or route cache files. Controller groups
  require a closure and a literal controller class or full class-name string.
  Dynamic controllers and method names remain unresolved. It does not resolve
  group namespaces, container bindings, or registration callbacks.
- It does not resolve Laravel's static `HasMiddleware` declarations, custom
  middleware bodies, middleware groups, service provider changes, or runtime
  middleware configuration. Unknown declarations lower confidence.
- It follows resolved functions, static methods, `$this` calls, and methods on
  named parameter types. It also tracks direct local assignments such as
  `$action = new Action()` with an imported or full class name. It does not
  resolve container bindings, variable callables, traits, object copies,
  property receivers, or all overrides.
- Local object tracking replaces facts on reassignment and removes facts
  changed inside branches or unsupported statements. It does not merge branch
  types. Dynamic classes, anonymous classes, `new self`, `new static`,
  `new parent`, assigned factory results, and references are not supported
  local receiver sources. Direct factory chains can use collected PHPStan
  receiver types as described above.
  Constructor arguments are checked, but constructor bodies are not followed.
  Construction alone does not establish authentication.
- Call depth is limited to 16. Recursion and unresolved calls lower confidence.
- Simple branches, early returns, throws, exits, and short-circuit expressions
  are supported. Loops, exception handlers, and other complex control flow are
  not a complete execution model.
- Constructors, middleware side effects, request hooks other than the supported
  validation hook, and deferred work need separate review.
- Guard changes and custom user resolvers can change identity after a check.
  The rule does not model all such changes.
- Authentication does not prove permission to perform an operation.
- A type, a method name, or a request value does not prove that a value is safe.

Full CWE entry: https://cwe.mitre.org/data/definitions/306.html.
