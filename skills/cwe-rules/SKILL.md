---
name: cwe-rules
description: "Use this skill when you create, change, or review a CWE rule in this package. Trigger when work touches src/Rules, shared input detectors, assignment flow, rule NEON files, rule documents, CWE fixtures, or rule tests. Covers shared input detection, local assignment tracking, file names, report format, configuration, ignore comments, documents, fixtures, and tests."
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
- Put a clear list of known limitations in the rule document.
- Keep rule classes small. Move shared logic into a separate class.
  Examples: `CweReport`, `RequestInput`, `LocalAssignmentFlow`, `BladeTemplateScanner`.
- Before you write new logic, look for a class that you can use again.
- If the logic exists in another rule, move it into a shared class instead of copying/rewriting it.
- Use descriptive names for variables and methods.

## Shared input detection

- Every new or changed rule that checks request input must first read
  `src/LaravelRequestInput.php`, `src/RequestInput.php`, and
  `src/LaravelRequestInput.md`.
- Reuse `LaravelRequestInput::isInput()` to identify Laravel sources.
  Do not copy its method list, helper resolution, or request type checks
  into a rule or collector. This class detects sources; it is not a
  PHPStan rule and does not decide whether a value is safe.
- For direct HTML or SQL expression checks, reuse `RequestInput::inHtml()`
  or `RequestInput::inSql()`. Pass both `Scope` and `ReflectionProvider`
  to `inSql()` so it can detect Laravel sources.
- A collector that needs assignment or source facts can call
  `LaravelRequestInput::isInput()` during its own expression scan.
  Keep the facts that its rule needs. Do not add a second recursive scan
  when the existing scan can use the shared detector.
- Keep sink selection, escape checks, bindings, assignment tracking, and
  ratings separate from source detection. Do not use HTML escaping as
  SQL or shell protection. Do not treat validation or a string type as
  proof that input is safe.
- When a new rule needs another Laravel source, extend the shared
  detector and its tests instead of adding a rule-specific copy. Check
  the effect on all rules that use it. Keep existing behaviour unless
  the change is required, and document any change.
- Add shared detector tests for new sources and negative cases, including
  unrelated receivers and shadowed helpers. Add rule tests for unsafe
  input, accepted protections, and relevant edge cases. Check both the
  single-rule configuration and `extension.neon`.
- Keep the shared source list and limitations in `src/LaravelRequestInput.md`.
  Link to this document from rule documents instead of copying the list.

## Shared local assignment flow

- Before you add assignment tracking, read `src/LocalAssignmentFlow.php`,
  `src/Rules/Cwe79/Cwe79Collector.php`, and the flow use in `Cwe79Rule`,
  `Cwe78Rule`, and `Cwe89LaravelRule`.
- When a new or changed rule must follow local assigned values, use
  `LocalAssignmentFlow::sinks()`. Do not copy event sorting, variable storage,
  or scope handling into the rule. Rules that check direct expressions only
  do not need assignment flow.
- Use a PHPStan collector to record assignment and sink events. Register it
  with `phpstan.collector`. Use a rule for `CollectedDataNode` to read the
  events. In `RuleTestCase`, return the collector from `getCollectors()`.
- Process each file's events separately. Each event needs `kind`, `scope`,
  and `offset`. Use `kind: 'assignment'` with a `variable` name for assignments,
  or `kind: 'sink'` for output or calls. Sinks also need a report line.
  Keep the facts that the rule needs in each event.
- Use source token positions for offsets. Choose positions that preserve the
  supported evaluation order. Test assignments near sinks and document
  unsupported nested assignments.
- Keep facts separate by class and named function. Do not mix closure facts
  with the outer scope. Add explicit closure support or document its limitations.
- Give `sinks()` a resolver with the event, current scope's variable facts,
  and assignment flag as arguments. The resolver returns the new facts.
  The flow saves assignment facts and returns `[sinkEvent, resolvedFacts]`
  pairs for reports. A replacement assignment must replace the old facts.
  A copied value must keep the facts from the time of the copy.
- For `.=` support, record the target variable as a dependency as well as
  variables in the new expression. This keeps the earlier value.
- Keep source detection, protections, sink selection, and report ratings in
  the detector, collector, or rule that owns them. The shared flow must not
  treat an HTML escape as SQL or shell protection.
- For HTML facts, reuse `RequestInput::inHtml()` with its optional variable
  callback. The collector can record each variable name and return `false`
  to continue the scan. Accepted HTML escapes and numeric casts stop the scan.
  Do not add a separate variable scan that bypasses these protections.
- Add tests for copies, replacement assignments, concatenation, `.=` when
  supported, interpolation, accepted protections, unknown variables, separate
  scopes, and file isolation. Check positive and negative cases through both
  the single-rule configuration and `extension.neon`.
- If the shared flow changes, run its unit tests and the rule tests for all
  callers. Keep their ratings and reports unchanged unless the task requires
  a change.
- State that this helper processes source order only. It does not merge
  branches, repeat loops, or follow values between functions. Do not describe
  it as full data-flow analysis.

## File names and locations

For a rule for CWE-NN, use these files:

| File | Purpose |
|------|---------|
| `src/Rules/CweNN/CweNNRule.php` | Rule class. Add a suffix for a different sink, for example `CweNNBladeRule.php`. |
| `src/Rules/CweNN/CweNNRule.md` | Rule document. It has the same name as the class. |
| `config/rules/cweNN.neon` | Service registration only. |
| `config/cweNN.neon` | Public file for one rule. It includes `parameters.neon` and `rules/cweNN.neon`, relative to `config/`. |
| `extension.neon` | Includes `config/parameters.neon` one time and each `config/rules/*.neon` file. |
| `tests/fixtures/CWE-NN/` | All fixtures for this CWE. |
| `tests/fixtures/shared/` | Fixtures that more than one CWE uses. |
| `tests/Integration/CweNNRuleTest.php` | PHPStan rule test. |
| `tests/Unit/` | Tests for shared classes that do not run PHPStan. |

Do not include `config/parameters.neon` in a `config/rules/*.neon` file. PHPStan stops if it
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

- Register each rule as a service in `config/rules/cweNN.neon`:

```neon
services:
    -
        class: Perturbatio\PhpstanCwe\Rules\CweNN\CweNNRule
        arguments:
            minProbability: %phpstanCwe.minProbability%
        tags:
            - phpstan.rules.rule
```

- Put all package parameters under `phpstanCwe` in `config/parameters.neon`.
- Add each new parameter to `parametersSchema`.
- Register a service for each class that the rule needs.
- Give a default that works in a normal project. If the default path is
  not in the project, skip it. If the user sets a path that does not
  exist, stop with an error.
- Add the rule to `extension.neon` and make a public `config/cweNN.neon` file.

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

- An ignore annotation must apply to only one finding. Put it on the same line before
  the finding or on the line before it.
- Report an ignore annotation that has no matching finding with the identifier
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
7. The known limitations.
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
  limitations.
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
- Test the probability limitations: `-1` and `101` cause an error. A score equal
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
