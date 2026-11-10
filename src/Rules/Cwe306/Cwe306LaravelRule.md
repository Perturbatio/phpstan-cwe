# CWE-306: Missing authentication for critical function in Laravel

This rule checks Laravel HTTP routes that call a configured critical
function or method. A critical operation is an operation that your application
requires a caller to authenticate before it runs. The rule does not assume that
all database writes or all POST routes require authentication.

The rule uses PHP syntax trees. It does not start the application or run Artisan.
Laravel is not a package dependency. The supported syntax includes route closures,
arrow functions, controller actions, and invokable controllers.

See the [future plans](Cwe306LaravelRule.future-plans.md) for proposed Eloquent
delete detection. These planned checks are not yet available.

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
or `Class::method` names. Name comparison is not case-sensitive. Do not list a
valid public operation, such as a contact form submission.

If the list is empty, the rule reports one configuration error per analysis:
`phpstanCwe.cwe306Configuration`. It does not scan for critical operations until
you configure at least one operation. This error is not a vulnerability finding.
The `minProbability` setting does not filter it.

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
bindings. The rule therefore checks only an exact configured method on that
requested class. It does not follow its body or use it to establish a user
identity or an authentication guarantee. Container calls lower confidence:
these routes score 80% with confirmed empty middleware, or 40% when middleware
is unknown.

String or dynamic class arguments, unpacked arguments, direct chained calls,
other container methods, and calls through a stored container are not supported.
A local function that replaces `app` is not accepted as Laravel's helper.

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
  `require`, controller groups, dynamic route handlers, or route cache files.
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
  `new parent`, factories, and references are not supported receiver sources.
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
