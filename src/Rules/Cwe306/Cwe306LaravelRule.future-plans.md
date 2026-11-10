# CWE-306 Laravel: Future plans

## Detect Eloquent delete calls

### Goal

Let a project require authentication before any Eloquent model delete call.
Report a supported HTTP route that reaches such a call without a supported
authentication control.

This is a plan, not current functionality. Configuration names below are
proposals.

### Scope

Start with these calls:

```php
use App\Models\User;
use App\Models\AnotherModel;

$user->delete();
User::find($id)->delete();
User::findOrFail($id)->delete();
AnotherModel::where('name', $value)->delete();
User::query()->whereKey($id)->delete();
```

Cover typed model parameters, model subclasses, Eloquent builders, and model
query chains whose receiver types PHPStan can establish. Follow these calls
through the existing supported route, controller, and helper paths.

Do not treat every method named `delete` as an Eloquent operation. Do not
include raw SQL, the base database query builder, relation deletion, `destroy`,
`forceDelete`, `deleteQuietly`, or deferred jobs in the first stage. Define and
test their behaviour before adding them.

CWE-306 concerns authentication. A policy or a permission check is not a
replacement for an authentication control. This feature must not claim to
detect missing permission to delete a particular record.

### 1. Confirm the type evidence

- Check PHPStan's receiver types for each example, with and without Larastan.
- Use model and builder reflection, including subclass and generic model
  information. Do not infer a model from its class name or a method name.
- Check nullable and union receiver types. A model-or-null receiver can identify
  a possible deletion. Null does not provide authentication. An unrelated
  object alternative must remain uncertain.
- Check custom `delete`, `find`, and `where` overrides. Do not assume that a
  custom method has the standard Eloquent behaviour.
- Keep Larastan optional unless the type checks establish that it is required.
  Document the supported dependency combination and unresolved cases.

### 2. Add explicit configuration

Proposed project configuration:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon

parameters:
    paths:
        - app
        - routes
    phpstanCwe:
        cwe306DetectEloquentDeletes: true
        cwe306CriticalOperations: []
```

- Default `cwe306DetectEloquentDeletes` to `false`. Existing projects must not
  gain new vulnerability findings without enabling the option.
- When enabled, treat supported Eloquent delete calls as critical operations.
  Keep the existing explicit function and method list available.
- Report `phpstanCwe.cwe306Configuration` only when both detection sources are
  disabled: the explicit list is empty and Eloquent detection is off.
- Validate the option through the shared parameter schema and both public
  configuration entry points. Do not add a wildcard syntax to method names.

### 3. Collect resolved call facts

The current scanner reparses files and tracks a limited set of receiver types.
It cannot establish the receiver type in `User::find($id)->delete()`.

- Add a PHPStan collector for relevant call nodes. Read the receiver type from
  `Scope` while PHPStan analyses the original file.
- Record serializable facts, not `Scope`, reflection, type, or AST objects.
  Include the file, source position, resolved operation, and whether the
  evidence is complete.
- Join facts to the scanner's AST by file and source position. A line alone
  cannot distinguish two calls on the same line.
- Keep the scanner's existing route and authentication analysis. Use collected
  facts to identify critical calls, not to decide whether a path requires a
  user.
- Resolve each call once. Do not add a second independent route walker or
  duplicate the middleware and request-hook logic.

### 4. Integrate with execution paths and reports

- Apply a collected critical-call fact at the call's execution point. Preserve
  receiver and argument evaluation order.
- Keep protected paths, guest paths, and stopped paths separate. A delete call
  after a check is protected only when all paths that reach it require a user.
- Do not scan a closure body only because the closure is created. Keep
  unsupported execution paths at lower confidence.
- Preserve authentication middleware, including `auth:sanctum`, constructor
  middleware, supported form requests, logout handling, and call depth limits.
- Keep `phpstanCwe.cwe306`, high severity, the MITRE link, route location,
  probability filtering, and inline ignore reasons.
- Keep severity separate from confidence. A known model type identifies a
  possible critical operation; it does not prove that the caller is safe.
- Define stable operation names for model and builder deletions. Retain the
  affected model name when known. Deduplicate facts and explicit configuration
  when both identify the same operation on one route.
- Do not report an isolated controller method without a supported route.

### 5. Add regression tests before implementation

Use Pest datasets for positive, negative, and edge cases:

| Area | Required cases |
|------|----------------|
| Model calls | Typed instance, inherited model, `find`, `findOrFail`, assigned result |
| Builder calls | `where`, `query`, chained filters, assigned builder |
| Authentication | Public route, `auth`, `auth:sanctum`, removed middleware, enforced branch, logout |
| Request lifecycle | Protected action, delete before `authorize`, custom lifecycle |
| Type limits | Nullable model, mixed receiver, unrelated union member, custom method override |
| Negative cases | Unrelated `delete`, raw query builder, excluded method names, deferred closure |
| Execution order | Delete in an argument, stopped argument, unreachable delete, nullsafe call |
| Call paths | Controller, service helper, cross-file call, recursion and depth limit |
| Configuration | Option off, option on with empty list, both sources enabled, invalid option type |
| Reports | Identifier, severity, confidence, MITRE link, route line, operation name, deduplication |

Test the collector's serialized output and its source-position join. Include
two delete calls on one line and files with the same line numbers.

Add integration fixtures for real Eloquent and Larastan type resolution. Local
test doubles alone must not establish support for real Eloquent chains.
Check both `extension.neon` and `config/cwe306-laravel.neon`. Keep tests for
projects without Laravel or Larastan.

### 6. Document and validate

- Update the README and rule document with runnable configuration, public and
  protected route examples, dependency requirements, and known limits.
- State that `find` can return null and that the rule does not check null
  dereferences or record permissions.
- Run `composer format`, then `composer analyse`.
- Run targeted Pest tests with `--no-tia` during implementation.
- After the regression batch is complete, run the full coverage and mutation
  checks. Use `--no-tia` and cap parallel mutation testing at `--processes=16`.
  Do not hide escaped behavioural mutations.

### Completion criteria

The feature is complete when the supported model and builder examples produce
a finding on a public route, accepted authentication controls stop that
finding, unrelated delete methods do not match, and both configuration entry
points behave the same. Unresolved types must not be presented as confirmed
Eloquent operations or complete authentication analysis.

MITRE reference: https://cwe.mitre.org/data/definitions/306.html.
