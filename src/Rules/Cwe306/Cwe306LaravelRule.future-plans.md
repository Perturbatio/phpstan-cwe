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

## Match critical operations with patterns

### Goal

Let a project require authentication for a group of methods without listing
each method separately.

Requested examples:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Actions\Data\DeleteOldRecordsAction\*
            - App\Services\*::delete
```

The intent is to cover actions in `App\Actions\Data\DeleteOldRecordsAction` and `delete` methods
on service classes. These examples are proposed syntax. The current validator
rejects them.

This feature selects critical operations. It does not add receiver type
resolution, container resolution, or new execution paths. The Eloquent plan
above addresses a separate detection gap.

### Questions to resolve before implementation

1. Should patterns use `cwe306CriticalOperations`, or a separate parameter such
   as `cwe306CriticalOperationPatterns`? A separate parameter makes the
   difference between an exact name and a pattern explicit.
2. Should `*` match one namespace segment, or include child namespaces? Should
   `**` be available for recursive namespace matching?
3. What does `App\Actions\Data\DeleteOldRecordsAction\*` select: functions, classes, or methods on
   those classes? Should the user instead write
   `App\Actions\Data\DeleteOldRecordsAction\*::*` to select methods explicitly?
4. If a namespace pattern selects action classes, does it select every method,
   only public methods, or only entry methods such as `__invoke` and `handle`?
   Should constructors and magic methods be excluded?
5. Should a class pattern match the runtime receiver class, the class that
   declares an inherited method, or either class? How should an override in a
   child class affect the match?
6. Should method-name patterns such as `delete*` be supported in the first
   version? Are `?`, character ranges, or regular expressions needed? A small
   initial syntax is easier to validate and explain.
7. Should projects be able to exclude specific public operations from a broad
   pattern? If so, which rule takes priority when an exact name, an inclusion
   pattern, and an exclusion match the same operation?
8. Should a valid pattern with no observed matches produce a diagnostic?
   Analysed paths can contain only part of an application, so no observed match
   does not establish a configuration error.
9. Should reports show only the resolved operation, or also the configuration
   pattern that selected it? The operation must remain clear when several
   patterns match.

### 1. Define the configuration contract

- Resolve the questions above and publish a small matching table before adding
  syntax. Include direct children, child namespaces, inherited methods, and
  names that must not match.
- Keep existing exact function and `Class::method` entries valid. Preserve
  case-insensitive comparison and optional leading namespace separators.
- Reject malformed patterns with a clear configuration error. Do not silently
  discard invalid entries or treat them as exact names.
- Match the full symbol. A prefix such as `App\Services` must not also match
  `App\ServicesExtra`.
- Use one platform-independent matching definition. Do not use filesystem glob
  behaviour for PHP symbol names or interpret user input as a regular expression.
- Treat a valid configured pattern as an enabled detection source when checking
  for empty configuration. Coordinate this with the proposed Eloquent option.

### 2. Add a shared operation matcher

- Separate pattern validation and matching from route and authentication
  analysis. Keep the helper specific to operation selection until another rule
  has the same contract.
- Normalise exact names and patterns once during construction. Keep an exact
  lookup for existing entries.
- Compile supported patterns once, with literal characters escaped and complete
  symbol boundaries enforced. Do not build a new expression at each call.
- Return enough information to identify the concrete matched operation.
  Preserve existing exact-name report behaviour.
- Do not enumerate or execute application classes to expand patterns. Match
  symbols discovered by the supported static analysis.

### 3. Use the matcher at each operation check

- Replace direct critical-operation map checks consistently. Cover ordinary
  calls, route entry actions, inherited bodies, and unresolved external bodies
  whose symbol is known.
- Check direct route actions after their supported request lifecycle, as the
  current rule does for exact critical operations.
- Preserve receiver and declaring-class information until inheritance matching
  is complete. Do not lose the concrete operation name in a wildcard report.
- Keep supported authentication controls, score calculation, call limits, and
  route-level reporting unchanged.
- Deduplicate overlapping patterns and exact entries. Matching the same call
  several times must not produce several findings or increase confidence.
- Do not assume that a pattern match proves public access. Unknown middleware
  and unresolved calls must retain their current confidence limits.

### 4. Add tests

| Area | Required cases |
|------|----------------|
| Compatibility | Exact function and method names, case differences, leading separator |
| Namespaces | Direct child, nested child, adjacent namespace, global namespace |
| Methods | Matching `delete`, unrelated method, selected action entry methods |
| Inheritance | Parent declaration, child receiver, child override, external parent |
| Configuration | Empty list, pattern-only list, malformed syntax, unsupported metacharacters |
| Overlap | Two patterns, duplicate pattern, exact name plus pattern |
| Routes | Closure, controller action, invokable controller, service helper |
| Controls | Public route, `auth`, `auth:sanctum`, request authorization, logout |
| Limits | Dynamic receiver, container call, deferred callback, unknown middleware |
| Reports | Concrete operation, identifier, route line, severity, confidence, ignore reason |

Test the matcher directly, then test its use through the scanner. Include
positive and negative cases for every agreed wildcard boundary. If exclusions
are accepted, test their priority explicitly.

Run integration tests with both package configuration entry points. Confirm
that a pattern-only configuration does not produce
`phpstanCwe.cwe306Configuration`. Check that unrelated rules keep their existing
behaviour.

### 5. Document and validate

- Add README and rule-document examples for action namespaces and service
  methods. State whether each pattern includes child namespaces and inherited
  methods.
- Explain that pattern matching does not resolve calls such as `$action()` or
  `app(Action::class)()` unless separate support is added.
- Describe the risk of selecting helper or public methods too broadly.
  Authentication and record-specific permission remain separate concerns.
- Run `composer format`, then `composer analyse`.
- Use targeted Pest runs with `--no-tia` during implementation. Run the full
  coverage and mutation checks after the test batch is complete. Cap parallel
  mutation tests at `--processes=16`.

### Completion criteria

The feature is complete when the agreed action and service patterns select
exactly the documented operations, existing exact entries keep their behaviour,
and protected routes do not produce new findings. Overlapping matches must not
produce duplicate findings. Invalid patterns must fail explicitly.

## Track local object types from assignments

### Goal and scope

Resolve calls on objects created in local variables:

```php
use App\Actions\Data\DeleteOldRecordsAction;
use Illuminate\Support\Facades\Route;

Route::get('test', function () {
    $action = new DeleteOldRecordsAction();
    $action->execute();
});
```

With `App\Actions\Data\DeleteOldRecordsAction::execute` configured as a
critical operation, this public route must produce a finding.

Start with direct assignments of named `new` expressions. Support full class
names and imported names in route closures, controller methods, and supported
helpers. This does not require Larastan or a new configuration option.

### Implementation steps

1. Extend `LaravelAuthenticationScanner::flow()` assignment handling. It
   currently removes the variable's known type. For a direct named `new`
   expression, replace the previous type with the resolved class instead.
2. Record the type only after evaluating the assignment expression. Preserve
   constructor argument evaluation and stopped paths. Do not treat construction
   as proof of authentication or complete constructor analysis.
3. Use the existing method-call resolution and critical-operation checks for
   later calls on that variable. Do not add a separate operation detector.
4. Replace or remove the stored type on every supported reassignment. Keep
   variable facts separate between functions, methods, and closures.
5. Handle branch changes before retaining types across statements. A conditional
   reassignment must not leave a stale parameter type or make one branch's new
   type apply to every path. Keep a type after a branch only when the supported
   analysis establishes it for all continuing paths; otherwise remove it.
6. Keep dynamic class names, anonymous classes, reference assignments, object
   aliases, factories, container calls, and property or array targets outside
   the initial supported scope. Unsupported changes must not preserve a type
   that can falsely establish authentication.

### Questions to resolve

1. Should the first version merge equal types across branches, or remove facts
   for all variables assigned in a branch? Choose a conservative approach and
   document its limits.
2. Should `new self` and `new static` be supported initially? If so, preserve the
   existing distinction between the declaring class and the runtime receiver.
3. Should object copies such as `$other = $action` be a separate stage, or use
   the proposed PHPStan type collector? Do not add partial alias tracking
   without defining reassignment and reference behavior.

### Tests and completion criteria

Add positive and negative Pest cases for direct construction, imported and full
class names, unrelated methods, replacement objects, unknown reassignment,
separate scopes, and assignments inside branches. Include a typed request
replaced on one branch to ensure that a stale type cannot establish
authentication. Test constructor arguments that contain critical calls or stop
execution.

Check public and authenticated routes, including `auth:sanctum`, and calls
through controllers and helpers. Confirm the report identifier, operation,
route line, confidence, and deduplication. Run integration tests through both
package configuration entry points.

Update the README FAQ and rule limits when support is available. Run
`composer format`, then `composer analyse`, and targeted Pest tests with
`--no-tia`. After the regression batch, run full coverage and mutation checks;
cap parallel mutation tests at `--processes=16`.

The feature is complete when the example above is detected, accepted
authentication controls stop the finding, and reassignment or branch-local
facts cannot cause an unsupported authentication guarantee.
