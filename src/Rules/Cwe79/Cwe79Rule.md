# CWE-79: Cross-site scripting

This rule finds request input in `echo` or `print`. It follows simple local
assignments before output. The output can put
untrusted text in an HTML page. The rule gives the report a **high** severity
and an **80%** probability score. This score is an estimate, not a measured
probability.

Unsafe PHP:

```php
$name = $_GET['name'];
$html = '<p>' . $name;
$html .= '</p>';
echo $html;
```

Safe PHP for HTML text and quoted HTML attributes:

```php
$name = $_GET['name'];
$html = '<p>' . htmlspecialchars($name) . '</p>';
echo $html;
```

The rule checks `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`. It also
checks the same [Laravel request sources](../../LaravelRequestInput.md#request-sources)
as the CWE-78 Laravel variant. This includes `request('key')`, input methods
on `Illuminate\Http\Request` objects and their subclasses, property reads,
array reads, and nullsafe input reads. PHPStan must know the request type
and resolve the global helper. A string type or validation result does
not make HTML output safe.

Unsafe Laravel example:

```php
echo request('name');
```

Protected Laravel example:

```php
echo htmlspecialchars(request('name'));
```

Laravel input checks are enabled in both `config/cwe79.neon` and `extension.neon`.
They use the shared `LaravelRequestInput` class, as the CWE-78 variant does.
The severity, probability, and `phpstanCwe.cwe79` identifier do not change.
The Blade rule does not change.

The rule follows copies, concatenation, `.=` assignments, interpolation, and
input passed to calls such as `trim()` or `strtoupper()`. These calls do not
escape HTML. A later assignment replaces the earlier facts for that variable.
Copies keep the facts from the time of the copy. Facts are kept separate for
each file, named function, and class method. The command and Laravel SQL rules
use the same `LocalAssignmentFlow` class to process assignment events.

The rule does not check JavaScript, CSS, URLs, templates, or other output functions.
It treats a call to
`htmlspecialchars()` or `htmlentities()` with only one argument as safe.
These functions use quote escape flags by default in PHP 8.1 and later.
In a namespace, use `\htmlspecialchars()` or `\htmlentities()` to show
that the call uses the PHP function and not a local function.
A cast to `int` or `float` is also safe for this check. Review all output
contexts by hand; this rule is not a full security check.

## Known limitations

- Assignment tracking uses source order, not execution paths. It does not
  merge branches or repeat loops. A later assignment in one branch can hide
  input from another branch.
- It does not follow values across function calls, closure captures,
  references, properties, array writes, or destructuring assignments.
- It checks direct output inside closures, but does not track their local
  assignments.
- It tracks `=` and `.=` only. Other assignment operators are not tracked.
- Assignments inside output expressions are not tracked in PHP evaluation
  order. Put assignments before output for this check.
- Calls with input arguments keep the input facts unless the rule accepts
  the call as an HTML escape. The rule does not inspect the function body.
- An unknown source does not prove that a value is safe.

Full explanation: https://cwe.mitre.org/data/definitions/79.html
