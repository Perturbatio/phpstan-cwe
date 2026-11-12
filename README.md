# PHPStan CWE rules

[![PHP Composer](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml/badge.svg)](https://github.com/Perturbatio/phpstan-cwe/actions/workflows/php.yml)

PHPStan CWE is a PHPStan extension. It reports possible security weaknesses
in PHP code and shows a severity, a probability score, a CWE reference, and a
stable error identifier for each finding.

The package requires PHP 8.3 or later and PHPStan 2.1 or later in the 2.x
series. Laravel is not required. Laravel-specific rules check supported
Laravel code when you use them.

Severity describes possible harm. The probability score estimates confidence
in the finding. It is not a measured probability of an attack. Each rule has
its own supported cases and limitations. Review its documentation before you
rely on a finding or treat the absence of a finding as proof of safety.
See the [rule documentation](src/Rules/) for supported cases and limitations.

---

## Installation

Install the package with Composer:

```sh
composer require --dev perturbatio/phpstan-cwe
```

Add the extension to your `phpstan.neon`. Set `paths` to the code you want
PHPStan to analyse. The full extension enables all rules, including the
Laravel-only CWE-306 rule.

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/extension.neon

parameters:
    level: 5
    paths:
        - app
        - routes
    phpstanCwe:
        cwe306CriticalOperations:
            - App\Actions\DeleteAccount::__invoke
```

Replace the example operation with an exact function or method that your
application requires callers to authenticate before it runs. The package
cannot choose critical operations safely for every application. If you leave
the list empty, CWE-306 reports a configuration error. See the
[CWE-306 Laravel rule document](src/Rules/Cwe306/Cwe306LaravelRule.md#configuration)
for wildcard patterns and other options.

Run PHPStan:

```sh
vendor/bin/phpstan analyse --configuration=phpstan.neon
```

The `auth` and `auth:sanctum` route middleware aliases are recognised by
default. `cwe306MiddlewareAliases` is for other aliases or an overridden
`auth` alias. `cwe306GlobalMiddleware` defaults to `null` (unknown); set it
only after you check the effective global middleware list.

`minProbability` defaults to `0`, so PHPStan reports findings at every
probability score. Raise it to filter lower-confidence findings.

## Configuration files

The default file (`vendor/perturbatio/phpstan-cwe/extension.neon`) enables all
rules.

To use one rule, include its public configuration file from `config/` instead
of `extension.neon`. For example, this file enables the PHP HTML rule:

```neon
includes:
    - vendor/perturbatio/phpstan-cwe/config/cwe79.neon
```

Rule configuration files are grouped as follows:

| Path | Purpose |
|------|---------|
| `extension.neon` | Main entry point. Enables all rules. |
| `config/cwe*.neon` | Public entry points for individual rules. |
| `config/parameters.neon` | Shared defaults and parameter schema. |
| `config/rules/` | Internal rule and collector service definitions. |

If your project does not use Laravel, select the rules you need instead of
including the full extension.

> [!NOTE]
> This package *helps* you find common CWE risks in your code. Use its checks as part of a broader security review.

### If you want to include all rules but ignore a specific rule.

You cannot exclude a specific rule once loaded, so it will still be processed by PHPStan, but you _can_ ignore the errors it produces.

In this case, add the following to your `phpstan.neon`
```neon
parameters:
    ignoreErrors:
        -
            identifier: phpstanCwe.cwe79 # ignore CWE-79 reports
```

This keeps all package rules enabled. A later version may add rules and
findings. Review the release notes when you upgrade.

### Setting Blade directories

The Blade rule scans `resources/views` and its child directories when the
directory exists. It runs when PHPStan analyses at least one PHP file.
Set other directories in `phpstan.neon` if necessary:

```neon
parameters:
    phpstanCwe:
        bladeDirectories:
            - resources/views
            - packages/shop/resources/views
```

Relative paths start at the current working directory. Set the list to
`[]` to stop the Blade scan.

To ignore one Blade raw echo, put a Blade comment immediately before it:

```blade
{{-- @phpstan-ignore phpstanCwe.cwe79 (This value is trusted.) --}}
{!! $trustedHtml !!}
```

An ignore annotation with no matching raw echo gets a report. See the
[Blade rule document](src/Rules/Cwe79/Cwe79BladeRule.md) for the exact placement.


[More Information](docs/further-reading.md)