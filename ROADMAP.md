# Roadmap

## TODOS

* refactor other rules to use a fingerprint for ignore annotations

## Plan

Add fingerprint ignore annotation functionality to **CWE-78, CWE-79 PHP and Blade, CWE-89 PHP and Laravel, and CWE-306
Laravel**, using CWE-95 as the reference.

### 1. Define the shared contract

Use one PHP directive style for all rules:

single line comment:

```php
// @phpstan-cwe-ignore phpstanCwe.cwe79[<fingerprint>] (Reviewed safe output)
```

multiline comment:

```php
/* @phpstan-cwe-ignore phpstanCwe.cwe79[<fingerprint>] (Reviewed safe output) */
```

Use the equivalent Blade comment for templates.

Require a 64-character fingerprint (sha256 hash) and a reason with at least two words. Each annotation must suppress
**one matching finding in its attached statement or raw echo**. Report invalid fingerprints, missing reasons, and stale
ignores through the existing diagnostic identifiers.

Keep severity, probability, detection behaviour, and CWE identifiers unchanged.

### 2. Extract shared fingerprint and ignore support

Extract reusable logic from CWE-95 for:

- Fingerprint generation with the rule identifier as an input.
- Annotation parsing and reason validation.
- Statement-bound, single-use matching and unmatched-ignore reporting.
- Copyable ignore tips, while retaining each rule’s safety advice.

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
3. Add collected finding support for CWE-89 PHP so ignores can be checked after findings are known.
4. Update Blade scanning to retain expressions and validate fingerprint annotations.
5. Update CWE-306 using route-specific findings, including multiple operations reached from one route.

Register shared services without duplicates when configurations are combined.

### 5. Preserve compatibility explicitly

Initially retain existing native PHPStan ignores and legacy Blade ignores. Document that **only package fingerprint
directives provide fingerprint validation**; native PHPStan suppression cannot offer that guarantee.

Do not silently remove old syntax. Treat mandatory migration as a separate breaking-change decision.

### 6. Add regression and mutation tests

For every rule, test valid suppression, invalid hashes, short reasons, stale ignores, duplicate findings, statement
boundaries, file isolation, and probability thresholds.

Verify stability across repeated processes, cached runs, comments, and blank lines. Verify relevant source changes
invalidate ignores. Test individual configurations and the full extension.

Require **100% executable-line coverage** and a **100% mutation score**, inspecting timeouts separately. Run mutations
with `--no-tia --parallel --processes=16`; use targeted runs during migration and a full run after shared changes.

### 7. Document and validate

Create one shared ignore guide, link from each rule document, and keep the README concise. Document placement,
compatibility, fingerprint limitations, and migration examples.

Finish with formatting, static analysis, the full test suite, coverage, mutation testing, and Composer validation.

## CWEs to implement:

### CWE-98: Improper Control of Filename for Include/Require Statement

* Detect `include`, `include_once`, `require`, and `require_once` calls with direct request input.

### CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

* Detect `new $className()` with direct request input.
* Detect `call_user_func($functionName)` with direct request input.
* Detect `call_user_func_array($functionName, $args)` with direct request input.
* Detect `forward_static_call($functionName, $args)` with direct request input.
* Detect `forward_static_call_array($functionName, $args)` with direct request input.