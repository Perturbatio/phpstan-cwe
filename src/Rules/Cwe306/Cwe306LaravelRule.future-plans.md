# CWE-306 Laravel: Future plans

## Detect Eloquent delete calls

### Goal

Let a project require authentication before any Eloquent model delete call.
Report a supported HTTP route that reaches such a call without a supported
authentication control.

This is a plan, not current functionality. Configuration names below are
proposals.

The previous completed label was incorrect. Configured chained-call matching
is now available, but automatic Eloquent delete selection and
`cwe306DetectEloquentDeletes` are not implemented.

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
  protected route examples, dependency requirements, and known limitations.
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

## COMPLETED: Match critical operations with patterns

Pattern matching is now supported in `cwe306CriticalOperations`. Use `*` for
one complete symbol segment and `!` before an exclusion pattern. Exclusions
take priority over exact names and inclusion patterns. See the
[rule document](Cwe306LaravelRule.md#configuration) for the supported contract.
The design questions and implementation steps below record the original plan.

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
on service classes. The service pattern is supported. The namespace-only action
pattern is not supported. Use
`App\Actions\Data\DeleteOldRecordsAction\*::*` to select methods on direct child
classes.

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
- Keep supported authentication controls, score calculation, call limitations, and
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

## COMPLETED: Extend critical operation patterns with glob syntax

### Goal

Let a project select methods across child namespaces and match part of a class
or method name. Keep the existing `cwe306CriticalOperations` parameter.

Globbing is now supported. The contract, implementation steps, and completion
criteria below record the implementation plan. See the
[rule document](Cwe306LaravelRule.md#configuration) for current configuration.

Proposed configuration:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Models\**\*::delete
            - App\Http\Controllers\**\*Controller::delete*
            - '!App\Models\Legacy\**\*::delete'
```

These are PHP symbol patterns, not directory patterns. The model pattern
selects resolved `delete` calls on classes in `App\Models` and its child
namespaces. It does not establish that these classes are Eloquent models.
It does not add support for unresolved Eloquent chains such as
`User::find($id)->delete()`. The Eloquent detection plan addresses that gap.

### 1. Define the matching contract

Use the following initial syntax:

| Syntax | Meaning |
|--------|---------|
| Literal name | Match the name without regard to case |
| `*` within an identifier | Match zero or more identifier characters, but not a namespace separator or `::` |
| `**` as a namespace segment | Match zero or more complete namespace segments |
| `!` at the start | Exclude matching operations, regardless of list order |

- Keep exact function and `Class::method` entries valid.
- Require every wildcard entry to use `Class::method` syntax. Do not add
  function-name globbing.
- Require each matched class, namespace, and method identifier to be non-empty
  and valid. For example, `*Controller` matches `Controller`, but `*` cannot
  match an empty class name.
- Allow partial wildcards in namespace, class, and method identifiers.
  `delete*` matches both `delete` and `deleteAccount`.
- Permit `**` only as a complete segment before the final class segment.
  Reject `App\Mod**els\*::delete`, `App\**::delete`, and `Class::**`.
- Reject adjacent recursive segments, such as `App\**\**\*::delete`, and runs
  of three or more stars. They add no useful matching behaviour.
- Do not add `?`, character ranges, brace expansion, regular expressions, or
  an escape syntax in the first version. Reject unsupported syntax explicitly.
- Preserve optional leading namespace separators and full-symbol matching.
  `App\Models` must not also select `App\ModelsExtra`.
- Keep exclusions stronger than exact names and inclusion patterns. An
  exclusion-only list must not enable detection.
- Do not report a configuration error for a valid pattern with no observed
  matches. Analysed files can contain only part of an application.

Required matching examples:

| Pattern | Operation | Match |
|---------|-----------|-------|
| `App\Models\*::delete` | `App\Models\User::delete` | Yes |
| `App\Models\*::delete` | `App\Models\Admin\User::delete` | No |
| `App\Models\**\*::delete` | `App\Models\User::delete` | Yes |
| `App\Models\**\*::delete` | `App\Models\Admin\Audit\User::delete` | Yes |
| `App\Models\**\*::delete` | `App\ModelsExtra\User::delete` | No |
| `App\Models\**\*::delete` | `App\Models\User::forceDelete` | No |
| `App\**\*Controller::delete*` | `App\Http\UserController::deleteAccount` | Yes |
| `App\**\*Controller::delete*` | `App\Controller::delete` | Yes |

### 2. Extend the existing matcher

- Change `CriticalOperationMatcher`. Do not add a second operation matcher,
  a filesystem glob library, or another route walker.
- Validate the symbol structure and wildcard tokens before compilation.
  Distinguish namespace segments, the class segment, and the method segment.
- Compile each accepted pattern once during construction. Escape literal
  characters and anchor the complete symbol.
- Compile recursive segments with their namespace separators. Zero matched
  segments must not require an extra separator.
- Keep generated expressions bounded by PHP identifier rules. Do not compile
  stars into unrestricted `.*` expressions that can cross symbol boundaries.
- Keep the exact-name lookup and current exact-name report behaviour.
- Keep the concrete matched operation in reports, not the glob expression.
- Keep duplicate and overlapping patterns from producing additional findings
  or changing confidence.

### 3. Preserve scanner behaviour

- Use the extended matcher at the existing operation checks. Do not add
  receiver type resolution, container binding resolution, or execution paths.
- For resolved inherited bodies, check both the runtime operation and the
  declaring operation. An exclusion that matches either takes priority.
- Do not apply a parent declaration match to a child override.
- For container assignments, match only the requested class and method.
  Do not follow the requested body or infer a declaring class.
- Keep route-entry request handling, authentication controls, stopped paths,
  call depth limits, confidence scores, probability filtering, and ignore
  reasons unchanged.

### 4. Add tests before implementation

Use Pest datasets for the matcher and regression tests for the scanner:

| Area | Required cases |
|------|----------------|
| Compatibility | Existing exact names, whole-segment stars, mixed case, leading separator |
| Partial names | Prefix, suffix, middle, multiple separated stars, zero matched characters |
| Recursive namespaces | Zero, one, and several segments; fixed segments after `**`; global namespace |
| Boundaries | Adjacent namespaces, empty identifiers, invalid identifier starts, extra separators, trailing content |
| Invalid syntax | Embedded `**`, adjacent `**`, terminal class `**`, method `**`, `***`, `?`, ranges, braces, function globs |
| Exclusions | Recursive and partial exclusions, either inheritance identity, both list orders, exact inclusion overridden |
| Reports | Concrete operation, identifier, severity, score, MITRE link, route and operation lines, deduplication |
| Controls | Public routes, `auth`, `auth:sanctum`, request authorization, logout, unknown middleware |
| Limits | Inherited bodies, child overrides, unresolved bodies, container assignments, dynamic calls, deferred closures |

Include direct assertions for the user's `App\Models\**\*::delete` example.
Confirm that it matches direct and nested classes but not `forceDelete`,
`deleteQuietly`, or unrelated namespaces.

Add integration fixtures through both `extension.neon` and
`config/cwe306-laravel.neon`. Use pattern-only configuration and recursive
exclusions. Check that no empty-configuration diagnostic is produced when an
inclusion pattern is present.

### 5. Document and validate

- Update the README and rule document with the syntax table, the recursive
  model example, exclusions, and positive and negative matching examples.
- State that `**` includes zero namespace segments. State that patterns match
  PHP symbols, not files, and do not prove Eloquent model inheritance.
- Retain the documented distinction between authentication and permission to
  delete a particular record.
- Run `composer format`, then `composer analyse`.
- Run targeted Pest tests with `--no-tia` during implementation.
- After the regression batch, run the full coverage and mutation checks.
  Use the mutation cache during iteration. Use `--no-cache` only when there
  is a specific need to check each mutation again. Cap parallel mutation
  testing at `--processes=16` with the required Composer patch applied.
- Investigate escaped behavioural mutations. Do not suppress them to pass
  the checks.

### Completion criteria

The feature is complete when the matching table and recursive exclusions work
through both package configurations, current valid patterns keep their
behaviour, and invalid syntax fails explicitly. Public routes must report the
concrete selected operation; accepted authentication controls must stop the
finding. The feature must not claim to detect unresolved Eloquent delete calls
or expand the scanner's supported execution paths.

## COMPLETED: Detect configured operations in chained calls

### Goal

Resolve the receiver of a chained method call so the existing critical
operation matcher can select it. Report the operation only when a supported
HTTP route reaches it without an accepted authentication control.

Configured chained-call matching is now supported. The steps below record
the implementation plan. See the rule document for the tested dependency
combination and the distinction between model and builder operations.
The supported examples include:

```php
use App\Models\Issues\ProductIssue;
use Illuminate\Support\Facades\DB;

ProductIssue::where('created_at', '<', $cutoff)->delete();
ProductIssue::query()->where('created_at', '<', $cutoff)->delete();
DB::table('issues')->where('created_at', '<', $cutoff)->delete();
$factory->createService()->execute();
```

The first stage supports statically named method calls whose receiver types
PHPStan can establish. It does not infer a receiver from a method name or the
first class name in a chain.

### 1. Confirm the current support and define operation identities

- Check the implementation, tests, and public configuration before changing
  the scanner. The Eloquent section above is marked completed, but its body
  describes proposed work. Confirm its actual status and correct the status
  and cross-references as part of implementation.
- Check PHPStan receiver and method reflection for each example, with and
  without Larastan. Record which dependency combination resolves each call.
  Keep Larastan optional unless the supported cases require it.
- Match the receiver class and the resolved declaring class through
  `CriticalOperationMatcher`. Preserve exclusion priority and exact-name
  report behaviour. Do not copy glob matching into the collector.
- For an Eloquent builder, use its builder identity. For a database query
  builder, use its query builder identity. Do not present a builder call as
  `App\Models\Issues\ProductIssue::delete`.
- Keep any known generic model information as supporting evidence, not an
  extra operation alias. Mapping builder calls to model patterns requires
  a separate, documented contract and is outside this stage.
- For general factory chains, use the resolved returned object's type, not
  the factory's class. Do not execute factories or resolve container bindings.

Proposed configuration for builder deletes:

```neon
parameters:
    phpstanCwe:
        cwe306CriticalOperations:
            - Illuminate\Database\Eloquent\Builder::delete
            - Illuminate\Database\Query\Builder::delete
```

Existing model patterns remain useful for resolved model calls. They do not
select builder operations merely because a model started the chain.
Do not add automatic critical-operation selection or a new configuration
parameter for this stage. The separate Eloquent detection option must remain
separate from configured operation matching.

### 2. Collect resolved receiver facts

- Reuse an existing call collector if one is available. Otherwise, add a
  PHPStan collector for chained method calls, including nullsafe calls.
  Read the receiver type from `Scope` during the original file analysis.
- Read method reflection rather than assuming that a fluent method returns
  its receiver. Respect custom return types, overrides, and builder subclasses.
- Store serializable facts: file, call start and end positions, method name,
  receiver and declaring class identities, and evidence completeness.
  Do not store `Scope`, reflection, type, or AST objects.
- Define conservative handling for nullable, union, intersection, mixed,
  and dynamic types before adding support. A model-or-null receiver can
  identify a possible call; an unrelated union alternative remains uncertain.
  Do not select one convenient type and treat the evidence as complete.
- Keep unresolved cases unknown. A known receiver type does not establish
  that an authentication control is absent or present.

### 3. Join facts to the existing scanner

- Pass collected facts through `Cwe306LaravelRule` to
  `LaravelAuthenticationScanner`. Register the collector through the shared
  rule service configuration used by both public entry points.
- Join facts by file and source positions, not line alone. Confirm that the
  PHPStan parser and scanner parser provide compatible positions. Test two
  calls on one line and calls at the same positions in different files.
- Use a collected fact only at the corresponding call execution point.
  Preserve receiver evaluation before argument evaluation, and evaluate both
  before applying the outer operation.
- Keep the existing route walker. Do not report calls in isolated methods
  without a supported route, or calls in deferred closures that are not run.
- Use the existing matcher once for all supported identities of the call.
  Deduplicate collected and existing syntax-based evidence. Overlapping
  patterns must not increase confidence or produce duplicate findings.
- Collected receiver facts select critical operations only. Do not use them
  to follow arbitrary external bodies or to establish authentication.
- Preserve request lifecycle handling, middleware, logout, stopped paths,
  recursion and depth limits, route-level reporting, and inline ignore reasons.
- Keep incomplete type or execution evidence at lower confidence. Preserve
  current scores for cases that the scanner already supports.

### 4. Add regression tests before implementation

| Area | Required cases |
|------|----------------|
| Eloquent builders | Static `where`, `query()->where`, multiple filters, custom builder subclass |
| Query builders | `DB::table()->where()->delete`, typed builder chains, unrelated facade |
| General chains | Typed factory return, inherited method, child override, changed return type |
| Types | Nullable, nullsafe, mixed, unrelated union member, intersection, unresolved generic |
| Matching | Builder exact name, recursive glob, declaring-class exclusion, model pattern alone |
| Order | Critical receiver call, critical argument, stopped receiver or argument, unreachable outer call |
| Controls | Public route, `auth`, `auth:sanctum`, request authorization, logout, unknown middleware |
| Paths | Closure route, controller, helper, cross-file call, deferred closure, depth limit |
| Fact joins | Same-line calls, different files, nested chains, missing or incomplete facts |
| Reports | Concrete operation, identifier, severity, confidence, MITRE link, route and operation lines, deduplication |

Add real Eloquent and Query Builder integration fixtures for the dependency
combinations established in step 1. Test doubles alone cannot establish
support for Laravel's dynamic builder methods. Check both `extension.neon`
and `config/cwe306-laravel.neon`, and retain tests without Laravel or Larastan.

### 5. Document and validate

- Update the README and rule document with both reported builder examples,
  working configuration, dependency requirements, and unresolved cases.
- Explain why model patterns do not select builder calls. State that this
  feature does not automatically classify every `delete` as critical.
- Keep authentication separate from permission to delete a particular record.
- Run `composer format`, then `composer analyse`.
- Run targeted Pest tests with `--no-tia`, then the full coverage check.
- Focus cached mutation testing on CWE-306 with `--path=src/Rules/Cwe306`.
  Keep all tests available. Run full mutation testing only if shared changes
  can affect other rules. Use `--no-cache` only for a specific need, and cap
  parallel mutation testing at `--processes=16` with the required patch.
- Investigate escaped behavioural mutations rather than suppressing them.

### Completion criteria

Both reported Eloquent chains and the Query Builder chain produce findings on
public routes when their resolved builder operations are configured. Accepted
authentication controls stop those findings. Model patterns alone do not
select builder operations. Unrelated or unresolved receivers must not be
presented as confirmed builder calls. Existing operation matching, exclusions,
execution order, report format, and both configuration entry points retain
their documented behaviour.
