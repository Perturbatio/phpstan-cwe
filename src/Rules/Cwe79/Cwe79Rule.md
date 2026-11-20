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
each file, named function, class method, closure, and arrow function.
The command and Laravel SQL rules
use the same `LocalAssignmentFlow` class to process assignment events.

For a directly invoked closure or arrow function, the rule checks its return
expressions for request input. It applies the same HTML escape checks.
It also follows a locally assigned arrow function when the code calls it.
For arrow functions, it follows captured local values from the time of the
assignment or direct call.

The rule does not check JavaScript, CSS, URLs, templates, or other output functions.
It treats a call to `htmlspecialchars()` or `htmlentities()` as safe when
it uses the default flags or a known flag value that includes `ENT_QUOTES`.
If the call gives an encoding, the rule accepts only a known `UTF-8` value.
These functions use quote escape flags by default in PHP 8.1 and later.
In a namespace, use `\htmlspecialchars()` or `\htmlentities()` to show
that the call uses the PHP function and not a local function.
A cast to `int` or `float` is also safe for this check. Review all output
contexts by hand; this rule is not a full security check.

## Known limitations

- Assignment tracking uses source order, not execution paths. It does not
  merge branches or repeat loops. A later assignment in one branch can hide
  input from another branch.
- It does not follow values across named function calls, closure captures,
  references, properties, array writes, or destructuring assignments.
- For a directly invoked closure, it does not follow local assignments or
  captured values into return expressions. It checks all return expressions
  without checking which branch runs.
- The rule follows captures into an arrow function's returned value. It does
  not follow captured values into output statements inside the arrow function.
- It tracks locally assigned arrow functions and their copies, not closures
  assigned to variables or other callback forms.
- It tracks `=` and `.=` only. Other assignment operators are not tracked.
- Assignments inside output expressions are not tracked in PHP evaluation
  order. Put assignments before output for this check.
- Calls with input arguments keep the input facts unless the rule accepts
  the call as an HTML escape. The rule does not inspect the function body.
- An unknown source does not prove that a value is safe.

For fingerprint-based ignore annotations, read the [shared ignore-annotation guide](../../Ignore/CweIgnore.md).
The fingerprint for output inside a closure or arrow function uses its
position in source order. Earlier versions did not include that position.
Review and replace old annotations for these findings. If you add, remove, or
move a closure or arrow function, review the annotations again.

Full explanation: https://cwe.mitre.org/data/definitions/79.html
