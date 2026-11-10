---
name: pest-mutation-testing
description: "Use this skill when you run Pest mutation testing, review escaped or uncovered mutants, or add tests to fix mutation results in this package."
license: MIT
---

# Pest mutation testing

Use this skill to find and fix mutation test failures in this package. Write
all comments and documents in ASD-STE100 Simplified Technical English.

## Run mutation tests

Focus mutation testing on the rule currently being changed. Include its
rule-specific collectors, scanners, and helpers in the mutation target.
For example, target the CWE-306 directory:

```sh
composer test:mutation:check -- --no-tia --parallel --path=src/Rules/Cwe306
```

Limit the mutation targets, not the available tests. Do not use a test filter
or select individual test files: keep all relevant tests available for the
coverage run and mutation checks.

Run the full mutation suite only when the change can affect other rules.
Examples include changes to shared input detection, shared assignment flow,
report generation, or common configuration. In those cases, omit `--path`:

```sh
composer test:mutation:check -- --no-tia --parallel
```

Agents must use `--no-tia` for Pest runs. These mutation scope requirements do
not replace the normal test and analysis requirements.

You can pass `--processes=16` with `--parallel` when the package's Composer
patch is applied. The patch removes `--processes=...` from mutation test
subprocess arguments. Run `composer patches-repatch --no-interaction` if
the installed dependencies do not have the patch. Without the patch,
Pest 5.3.5 passes this option to the test subprocess without `--parallel`.
The subprocess stops with an unknown-option error, which Pest counts as
a detected mutation. Do not use `--processes` without the patch.
Avoid using `--no-cache` except when you *need* to check each mutation again.
The Composer command fails on PHP warnings. A warning from changed code
must not count as a passing test.

## Read the result

- **Uncovered** means the test run did not execute the mutated code. Add a test
  that executes the code and checks its behaviour.
- **Escaped** means the code ran, but the tests did not detect the change. Add
  an assertion that checks the changed behaviour or value.
- Read the mutation name and source line. Check the code and existing tests
  before you change the implementation.

## Fix property and constant mutants

Coverage tools cannot show execution of a class property or constant when the
runtime does not execute its declaration. Use this order:

1. If reading the value is useful to callers, move it behind a descriptive
   getter method. Use the getter in the production logic.
2. Add a test that calls the getter and checks its expected value. This makes
   a changed value visible to mutation testing.
3. If a getter adds no useful behaviour, keep the property or constant.
   Add a test that checks its expected default value before the code uses it.
   Then ignore only that mutation.

Do not add a getter only to hide an uncovered property when it has no useful
meaning. Do not ignore a mutation without first adding a test for its default
value.

## Ignore a mutant

Use `@pest-mutate-ignore` only when there is no useful way to execute the
declaration itself. Put one explanatory single-line comment directly above
the ignore directive. The comment must state why the mutant is ignored and
which test checks the default value.

```php
// The property declaration cannot be covered; the rule test checks its default probability.
// @pest-mutate-ignore
private const int PROBABILITY = 80;
```

Keep the explanation accurate. Do not use the directive to hide an escaped
behavioural mutant.

## Verify the fix

- Re-run the mutation command with the same rule-specific targets. Run the
  full mutation suite only if the change can affect other rules.
- Confirm that the fixed mutants no longer appear as uncovered or escaped.
- Run `composer format` and `composer analyse` after changing PHP code.
- Do not change unrelated code or tests to improve the mutation score.
