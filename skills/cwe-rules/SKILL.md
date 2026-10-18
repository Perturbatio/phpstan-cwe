---
name: cwe-rules
description: "Use this skill when you create, change, or review a CWE rule in this package. Trigger when work touches src/Rules, rule NEON files, rule documents, CWE fixtures, or rule tests. Covers file names, report format, configuration, ignore comments, documents, fixtures, and tests."
license: MIT
---

# CWE rule conventions

Use these conventions for each new or changed rule. Write all comments and
documents in ASD-STE100 Simplified Technical English.

## Rule scope

- Make one rule for one CWE and one type of sink.
  Example: `Cwe79Rule` checks PHP output. `Cwe79BladeRule` checks Blade
  templates.
- Report only cases that the rule can support. Do not say that a value is
  safe only because it has a type.
- Put a clear list of known limits in the rule document.
- Keep rule classes small. Move shared logic into a separate class.
  Examples: `CweReport`, `RequestInput`, `BladeTemplateScanner`.
- Before you write new logic, look for a class that you can use again.
- Use descriptive names for variables and methods.

## File names and locations

For a rule for CWE-NN, use these files:

| File | Purpose |
|------|---------|
| `src/Rules/CweNNRule.php` | Rule class. Add a suffix for a different sink, for example `CweNNBladeRule.php`. |
| `src/Rules/CweNNRule.md` | Rule document. It has the same name as the class. |
| `rules/cweNN.neon` | Service registration only. |
| `cweNN.neon` | Public file for one rule. It includes `config.neon` and `rules/cweNN.neon`. |
| `extension.neon` | Includes `config.neon` one time and each `rules/*.neon` file. |
| `tests/fixtures/CWE-NN/` | All fixtures for this CWE. |
| `tests/fixtures/shared/` | Fixtures that more than one CWE uses. |
| `tests/Integration/CweNNRuleTest.php` | PHPStan rule test. |
| `tests/Unit/` | Tests for shared classes that do not run PHPStan. |

Do not include `config.neon` in a `rules/*.neon` file. PHPStan stops if it
includes one file more than one time.

## Rule class

- Implement `PHPStan\Rules\Rule` and add a `@implements Rule<...>` tag.
- Declare these constants in the rule:

```php
private const string SEVERITY = 'high';
private const int PROBABILITY = 80;
```

- Accept `int $minProbability = 0` in the constructor. Call
  `CweReport::isEnabled($minProbability, self::PROBABILITY)` in the
  constructor. This validates the value.
- Call `CweReport::isEnabled()` again in `processNode()`. Return `[]` if the
  score is less than the minimum.
- Make all reports with `CweReport::make()`. Do not use
  `RuleErrorBuilder` directly for a CWE report.
- For a report in a file that PHPStan does not analyse (for example a
  Blade view), give `$file` and `$line` to `CweReport::make()`.
- Resolve names with PHPStan when a name can refer to a different symbol.
  For example, use `ReflectionProvider` for a function in a namespace.
- Read named and positional arguments when a rule checks a function or
  method argument.

## Report format

`CweReport::make()` makes this message:

```text
CWE-NN: <reason> Severity: <severity>. Probability: <score>%. https://cwe.mitre.org/data/definitions/NN.html
```

- The error identifier is `phpstanCwe.cweNN`.
- The metadata has `cwe`, `severity`, `probability`, and `url`.
- Reports must be ignorable.
- Severity tells the possible harm. Probability tells the confidence in the
  finding. Keep these two values separate.
- Write the reason as a short sentence. Tell the developer what the rule
  found. Add the safe action if it is short.

## Configuration

- Register each rule as a service in `rules/cweNN.neon`:

```neon
services:
    -
        class: Perturbatio\PhpstanCwe\Rules\CweNNRule
        arguments:
            minProbability: %phpstanCwe.minProbability%
        tags:
            - phpstan.rules.rule
```

- Put all package parameters under `phpstanCwe` in `config.neon`.
- Add each new parameter to `parametersSchema`.
- Register a service for each class that the rule needs.
- Give a default that works in a normal project. If the default path is
  not in the project, skip it. If the user sets a path that does not
  exist, stop with an error.
- Add the rule to `extension.neon` and make a public `cweNN.neon` file.

## Templates and other non-PHP files

- Put the file scan in a scanner class. Keep the PHPStan rule small.
- Use a collector and a `CollectedDataNode` rule. Scan the files one time
  for each analysis.
- Report the path and line in the scanned file, not in a PHP file.
- Keep line numbers correct when you hide comments or text blocks.
- Do not report the same real file two times when paths overlap.
- For an instance ignore, use a comment in the syntax of the template with
  the PHPStan form:

```blade
{{-- @phpstan-ignore phpstanCwe.cwe79 (Reason) --}}
{!! $trustedHtml !!}
```

- An ignore must apply to only one finding. Put it on the same line before
  the finding or on the line before it.
- Report an ignore that has no matching finding with the identifier
  `phpstanCwe.ignoreUnmatched`.
- If a rule has an instance ignore, give each report a tip that shows the
  ignore comment. Tell the developer to use it only if they are sure that
  the finding is safe. Give the tip to `CweReport::make()` with the `$tip`
  argument. Do not put the tip in the message.

## Rule document

Put the document next to the rule class. Include:

1. The CWE number and name as the title.
2. What the rule finds and which sinks it checks.
3. The severity and probability score. Say that the score is an estimate.
4. A short unsafe example.
5. A short safe example.
6. The protections that the rule accepts.
7. The known limits.
8. Configuration and ignore instructions, if the rule has special
   instructions.
9. The full MITRE link:
   `https://cwe.mitre.org/data/definitions/NN.html`.

Update `README.md` when you add a rule, a public NEON file, a parameter, or
an identifier.

## Fixtures

- Put each fixture in the directory for its CWE.
- Add a short comment on each line that you test. Say `Report:` or
  `No report:` and give the reason.
- Include unsafe, safe, and edge cases. Also include cases that show known
  limits.
- Keep test line numbers correct when you add comments. Put comments on the
  same line when possible.
- Do not put non-rule fixtures in a directory that a scanner test scans.
- Configuration fixtures use paths relative to the project root for scan
  directories. Include paths are relative to the NEON file.

## Tests

Use Pest v5. Also use the `pest-testing` skill when you write tests.

- Put tests that use PHPStan in `tests/Integration`.
- Put tests for classes that do not need PHPStan in `tests/Unit`.
- Rule tests use a class that extends `PHPStan\Testing\RuleTestCase` and
  `uses()` for that class. The class must not be `final`.
- Check the exact message and line for each report in a rule test.
- Test the probability limits: `-1` and `101` cause an error. A score equal
  to the minimum gives a report. A score less than the minimum does not.
- In CLI integration tests, check that PHPStan's top-level `errors` is
  empty before you read file messages.
- Check the identifier, severity, score, MITRE link, file, line, and
  `ignorable` value.
- Test the full extension and the one-rule NEON file.
- Run these commands before you finish:

```sh
vendor/bin/pest
vendor/bin/phpstan analyse src --level=8 --no-progress
composer validate --no-check-publish
```
