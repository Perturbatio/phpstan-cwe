# CWE-89: SQL injection

This rule finds direct request input in SQL text sent to PDO or mysqli. It
also checks SQL text sent to `prepare()`: a parameter does not protect text
that is part of the query before the call to `prepare()`. The rule gives the
report a **high** severity and an **80%** probability score. This score is
an estimate, not a measured probability.

Unsafe PHP:

```php
$pdo->query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");
```

Safe PHP:

```php
$statement = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$statement->execute([$_GET['name']]);
```

The rule checks direct input from `$_GET`, `$_POST`, `$_COOKIE`, and
`$_REQUEST`. It also uses the [shared Laravel input detector](../../LaravelRequestInput.md)
for the global `request()` helper and supported input reads on typed
Laravel request objects and their subclasses. Helper aliases, property
reads, array reads, and nullsafe input reads are supported.
HTML and shell escaping do not protect SQL.

It checks PDO `query()`, `exec()`, and `prepare()`. It checks
mysqli `query()`, `real_query()`, `multi_query()`, and `prepare()`, and the
equivalent `mysqli_*` functions. It needs a known PDO or mysqli receiver for
method calls. It does not follow a value after assignment to a variable or
through a function. It does not prove that a query is safe. A cast to `int`
or `float` removes SQL syntax from a direct value.

Full explanation: https://cwe.mitre.org/data/definitions/89.html
