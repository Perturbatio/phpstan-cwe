# CWE-79: Blade raw output

This rule finds Blade raw echo tags in `.blade.php` files. A raw echo uses
`{!!` and `!!}`. Blade does not escape the value in this tag. If the value
comes from a user, the output can contain harmful HTML or script code. The
rule gives each report **high** severity and an **80%** probability score.
This score is an estimate, not a measured probability.

Unsafe Blade:

```blade
<p>{!! $name !!}</p>
```

Safer Blade for HTML text:

```blade
<p>{{ $name }}</p>
```

The rule checks Blade views in `resources/views` by default. It also checks
child directories. It ignores Blade comments, `@verbatim` blocks, escaped
raw tags that start with `@`, and raw tags that contain only a fixed string.
It does not follow variables to their source. It can report a safe value
that is deliberately trusted or already escaped. It cannot check each HTML
output context. Review each report before you change a template.

The rule scans views when PHPStan analyzes at least one PHP file. Use
`cwe79-blade.neon` to run only this rule. Use the `bladeDirectories`
parameter to set other view directories. Relative paths start at the
current working directory. For example:

```neon
parameters:
    phpstanCwe:
        bladeDirectories:
            - resources/views
            - packages/shop/resources/views
```

Full explanation: https://cwe.mitre.org/data/definitions/79.html
