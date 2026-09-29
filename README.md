# PHPStan CWE rules

This package reports potential web application weaknesses during PHPStan
analysis. The first rules check direct request input at HTML and SQL sinks.
The rules do not follow data through variables or functions. Use other
security checks and code review with these rules.

## Install

Install the package with Composer:

```sh
composer require --dev perturbatio/phpstan-cwe
```

Add the configuration file to your `phpstan.neon`:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon
```

The default file enables both rules. To use only one rule, include
`cwe79.neon` or `cwe89.neon` instead of `extension.neon`.

## Set a minimum probability score

The default minimum is `0`. Set a value from `0` to `100` in `phpstan.neon`:

```neon
parameters:
    phpstanCwe:
        minProbability: 80
```

Each initial rule has a probability score of `80`. A minimum of `81` stops
both rules from reporting. This score is an estimate of detection confidence,
not a measured probability of an attack. Severity is separate: each initial
rule reports **high** severity because the possible harm is high.

Each report gives a CWE number, a reason, a severity, a probability score,
and a link to the MITRE CWE site. Reports are ignorable PHPStan errors.
The stable identifiers are `phpstanCwe.cwe79` and `phpstanCwe.cwe89`.
The same data is in the PHPStan error metadata.

Read [CWE-79](src/Rules/Cwe79Rule.md) and
[CWE-89](src/Rules/Cwe89Rule.md) for examples and limits.
