---
name: pest-mutation-testing
description: "Use this skill when you run Pest mutation testing, review escaped or uncovered mutants, or add tests to fix mutation results in this package."
license: MIT
---

# Pest mutation testing

Use this skill to find and fix mutation test failures in this package. Write
all comments and documents in ASD-STE100 Simplified Technical English.

## Run mutation tests

Run the full mutation suite. Do not use a test filter. Mutation testing needs
the complete coverage run.

```sh
composer test:mutation:check -- --no-tia --parallel --no-cache
```

Agents must use `--no-tia` for Pest runs. The mutation command still runs the
full suite.

Do not pass `--processes` to mutation runs. Pest 5.3.5 passes this option to
the test subprocess without `--parallel`. The subprocess stops with an
unknown-option error. Pest then counts that error as a detected mutation.
Use `--no-cache` to check each mutation again.
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

- Re-run the full mutation command.
- Confirm that the fixed mutants no longer appear as uncovered or escaped.
- Run `composer format` and `composer analyse` after changing PHP code.
- Do not change unrelated code or tests to improve the mutation score.
