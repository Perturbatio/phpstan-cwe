# Roadmap

## CWEs to implement:

### CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

  * HIGH PRIORITY (>90% probability) - Detect `eval()` calls with direct request input.
  * MEDIUM PRIORITY (50% probability?) - Detect `eval()` with data where the source cannot be identified.
  * LOW PRIORITY (30% probability?) - Detect `eval()` usage.
  * IGNORE - Detect `assert()` calls with direct request input. (<PHP 8.0 Only, string eval not supported after that)
  * IGNORE - Detect `preg_replace()` calls with the `/e` modifier and direct request input. (<PHP 8.0 Only, string eval not supported after that)
  * IGNORE - Detect `create_function()` (REMOVED as of PHP 8.0.0) calls with direct request input.

Eval example:

BAD:
```PHP
$code = $_GET['code'];
eval($code); // CWE-95
```

Safe:
```PHP
$code = 'return 1 + 1;';
eval($code); // Dynamic evaluation, but not necessarily vulnerable
```

*Possibly* bad:
```PHP
$code = $_GET['code'];
if (is_numeric($code)) {
    eval($code); // CWE-95, but with some validation
}
```

### CWE-98: Improper Control of Filename for Include/Require Statement

  * Detect `include`, `include_once`, `require`, and `require_once` calls with direct request input.

### CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

  * Detect `new $className()` with direct request input.
  * Detect `call_user_func($functionName)` with direct request input.
  * Detect `call_user_func_array($functionName, $args)` with direct request input.
  * Detect `forward_static_call($functionName, $args)` with direct request input.
  * Detect `forward_static_call_array($functionName, $args)` with direct request input.