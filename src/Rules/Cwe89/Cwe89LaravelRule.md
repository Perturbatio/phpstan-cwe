# CWE-89: SQL injection in Laravel query builders

This rule finds dynamic values in raw SQL expressions passed to Laravel
Eloquent and Query Builder methods. It also checks `DB::select()`,
`DB::insert()`, `DB::update()`, and `DB::delete()`. It checks `whereRaw()`,
`orWhereRaw()`, `havingRaw()`, `orHavingRaw()`, `orderByRaw()`,
`groupByRaw()`, `selectRaw()`, and `fromRaw()`. It reports with **high**
severity and an **80%** probability score for request input. The score is
an estimate.

Unsafe PHP:

```php
$user = $_GET['username'];
$password = $_GET['password'];
DB::select("SELECT * FROM users WHERE username = '$user' AND password = '$password'");
```

Safe PHP:

```php
DB::select(
    'SELECT * FROM users WHERE username = ? AND password = ?',
    [request()->input('username'), request()->input('password')],
);
```

The rule reports unprotected dynamic values in the raw SQL expression. This
includes request values and values with an unknown source. The raw SQL
expression is the first argument. Values in the bindings argument are not
part of the SQL expression and do not cause a report. Static string, integer,
and float expressions do not cause a report.

The rule accepts `wrap()` on `Illuminate\Database\Grammar` and its subclasses
when the argument is known to be a string. For example:

```php
$wrappedColumn = $query->getGrammar()->wrap($column);
$query->orWhereRaw("FIND_IN_SET(?, {$wrappedColumn})", [$value]);
```

Here, `$column` must be a string. The grammar quotes the column identifier.
The query binds `$value` separately. The rule also accepts a named `value`
argument and follows local assignments of the wrapped result. It still
reports other unbound dynamic values in the same SQL expression.
It does not accept a raw expression object or an argument with an unknown
type. Laravel can return raw expressions from `wrap()` without quoting them.

Each report includes a tip to check these types when you use `wrap()`.
Add or correct parameter types so PHPStan can identify the string argument
and the Laravel grammar receiver. A string type alone does not make raw SQL
safe. Use bound parameters for values.

The rule follows simple local variable assignments and `.=` operations in
one function or method in source order. It supports the `DB` facade import and Laravel's
global `DB` alias. It reports direct request data with an **80%**
probability score.
When it cannot find the source of a dynamic value, it reports a warning with
a **45%** probability score. Both scores are estimates. A minimum
probability setting can hide the lower-confidence warnings.

Request detection uses the [shared Laravel input detector](../../LaravelRequestInput.md).
It checks the global `request()` helper, including imported aliases, and
supported input reads on typed `Illuminate\Http\Request` objects and
subclasses. This includes property, array, and nullsafe reads.
A different namespaced `request()` function is an unknown source, not a
known Laravel request source. Validation, HTML escaping, and shell
escaping do not protect SQL values. Use bound parameters.

The rule does not trace values across function calls or between functions.
It does not merge assignments from different branches or loops. Check
reports with conditional assignments with care. It does not check Laravel's
`DB::raw()` or raw connection methods. It can report a dynamic value that
was sanitised or is a trusted SQL fragment. Review such reports with care.
It does not prove that an expression is safe because it has a string type.
The rule assumes that grammar subclasses use Laravel's identifier quoting.
It does not check custom grammar implementations or the SQL position of a
wrapped result. Use wrapped results as identifiers, not as quoted string
values. Use bound parameters for values. If a user can select a column,
also check that the user has permission to use that column.

To see an example output of this rule run:
```vendor/bin/phpstan analyse tests/fixtures/CWE-89/laravel.php --configuration=config/cwe89-laravel.neon --level=0 --no-progress```

Full explanation: https://cwe.mitre.org/data/definitions/89.html
