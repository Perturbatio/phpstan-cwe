# CWE-79: Cross-site scripting

This rule finds direct request input in `echo` or `print`. The output can put
untrusted text in an HTML page. The rule gives the report a **high** severity
and an **80%** probability score. This score is an estimate, not a measured
probability.

Unsafe PHP:

```php
echo '<p>' . $_GET['name'] . '</p>';
```

Safe PHP for HTML text and quoted HTML attributes:

```php
echo '<p>' . htmlspecialchars($_GET['name']) . '</p>';
```

The rule checks `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`. It does not
follow a value after assignment to a variable. It does not check JavaScript,
CSS, URLs, templates, or other output functions. It treats a call to
`htmlspecialchars()` or `htmlentities()` with only one argument as safe.
These functions use quote escape flags by default in PHP 8.1 and later.
In a namespace, use `\htmlspecialchars()` or `\htmlentities()` to show
that the call uses the PHP function and not a local function.
A cast to `int` or `float` is also safe for this check. Review all output
contexts by hand; this rule is not a full security check.

Full explanation: https://cwe.mitre.org/data/definitions/79.html
