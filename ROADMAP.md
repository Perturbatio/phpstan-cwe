# Roadmap

## TODOS

* refactor other rules to use fingerprint-based ignore annotations

## Plan

Add fingerprint-based ignore-annotation support to **CWE-78, CWE-79 PHP and Blade, CWE-89 PHP and Laravel, and CWE-306
Laravel**, using CWE-95 as the reference.

### 1. Define the shared contract

Use one PHP directive style for all rules:

single line comment:

```php
// @phpstan-ignore phpstanCwe.cwe79.<fingerprint> (Reviewed safe output)
```

multiline comment:

```php
/* @phpstan-ignore phpstanCwe.cwe79.<fingerprint> (Reviewed safe output) */
```

Use the equivalent Blade comment for templates.

Require a 64-character fingerprint (sha256 hash) and a reason with at least two words. Each annotation must suppress
**one matching finding in its attached statement or raw echo**. Report invalid fingerprints, missing reasons, and stale
ignore annotations through the existing diagnostic identifiers.

Keep severity, probability, detection behaviour, and CWE identifiers unchanged.

### 2. Extract shared fingerprint and annotation support

Extract reusable logic from CWE-95 for:

- Fingerprint generation with the rule identifier as an input.
- Annotation parsing and reason validation.
- Statement-bound, single-use matching and unmatched-annotation reporting.
- Copyable annotation tips, while retaining each rule’s safety advice.

Keep PHP comment collection and Blade comment scanning separate. Preserve existing CWE-95 fingerprints during
extraction.

### 3. Define fingerprint inputs for each rule

| Rule               | Finding identity                                                     |
|--------------------|----------------------------------------------------------------------|
| CWE-78             | Scope, command sink, command expression, detected sources            |
| CWE-79 PHP         | Scope, output sink, output expression, detected sources              |
| CWE-79 Blade       | Template path and raw-echo expression                                |
| CWE-89 PHP/Laravel | Scope, database operation, query expression, detected sources        |
| CWE-306            | Route identity, critical operation, relevant authentication evidence |

Exclude line numbers, token offsets, comments, and runtime object identities. Sort unordered inputs. Document which code
changes require a new review. Reuse CWE-95’s closure isolation where needed without expanding detection scope.

### 4. Migrate incrementally

1. Move CWE-95 onto the shared implementation and verify compatibility.
2. Update CWE-78, CWE-79 PHP, and CWE-89 Laravel collectors.
3. Add collected finding support for CWE-89 PHP so annotations can be checked after findings are known.
4. Update Blade scanning to retain expressions and validate fingerprint annotations.
5. Update CWE-306 using route-specific findings, including multiple operations reached from one route.

Register shared services without duplicates when configurations are combined.

### 5. Preserve compatibility explicitly

Initially retain existing native PHPStan annotations and legacy Blade annotations. Document that **only package fingerprint
directives provide fingerprint validation**; native PHPStan suppression cannot offer that guarantee.

Do not silently remove old syntax. Treat mandatory migration as a separate breaking-change decision.

### 6. Add regression and mutation tests

For every rule, test valid suppression, invalid hashes, short reasons, stale annotations, duplicate findings, statement
boundaries, file isolation, and probability thresholds.

Verify stability across repeated processes, cached runs, comments, and blank lines. Verify relevant source changes
invalidate annotations. Test individual configurations and the full extension.

Require **100% executable-line coverage** and a **100% mutation score**, inspecting timeouts separately. Run mutations
with `--no-tia --parallel --processes=16`; use targeted runs during migration and a full run after shared changes.

### 7. Document and validate

Create one shared ignore-annotation guide, link from each rule document, and keep the README concise. Document placement,
compatibility, fingerprint limitations, and migration examples.

Finish with formatting, static analysis, the full test suite, coverage, mutation testing, and Composer validation.

## CWEs to implement:

### CWE-98: Improper Control of Filename for Include/Require Statement

* Detect `include`, `include_once`, `require`, and `require_once` calls with direct request input.
* Detect the same methods with indirect request input (e.g., `$file = $_GET['file']; include $file;`).


### CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

#### Class instantiation
  * Detect `new $className()` with direct request input.
  * Detect `new $className($args)` with direct request input.
  * Detect `new $className(...$args)` with direct request input.
  * Detect `new $className($arg1, $arg2, ...)` with direct request input.
#### ReflectionClass
  * Detect `ReflectionClass($className)` with direct request input.
  * Detect `ReflectionClass::newInstance($args)` with direct request input.
  * Detect `ReflectionClass::newInstanceArgs($args)` with direct request input.
  * Detect `ReflectionClass::newInstanceWithoutConstructor()` with direct request input.

#### ReflectionMethod
  * Detect `ReflectionMethod($className, $methodName)` with direct request input.
  * Detect `ReflectionMethod::invoke($object, $args)` with direct request input.
  * Detect `ReflectionMethod::invokeArgs($object, $args)` with direct request input.

#### ReflectionFunction
  * Detect `ReflectionFunction($functionName)` with direct request input.
  * Detect `ReflectionFunction::invoke($args)` with direct request input.
  * Detect `ReflectionFunction::invokeArgs($args)` with direct request input.

#### ReflectionProperty
  * Detect `ReflectionProperty($className, $propertyName)` with direct request input.
  * Detect `ReflectionProperty::getValue($object)` with direct request input.
  * Detect `ReflectionProperty::setValue($object, $value)` with direct request input.

#### ReflectionParameter
  * Detect `ReflectionParameter($functionName, $parameterName)` with direct request input.

#### Variable functions and methods
* `$func()`
* `$obj->$method()`
* `Class::$method()`

* Detect `call_user_func($functionName)` with direct request input.
* Detect `call_user_func_array($functionName, $args)` with direct request input.
* Detect `forward_static_call($functionName, $args)` with direct request input.
* Detect `forward_static_call_array($functionName, $args)` with direct request input.
* is_a() / is_subclass_of() - with request input - Checks class type or inheritance. With $allow_string = true, a string class name from user input can trigger autoloading before type checks complete.

From the PHP Docs:

    allow_string - If this parameter is set to false, a string class name as object_or_class is not allowed. This also prevents calling the autoloader if the class doesn't exist.
