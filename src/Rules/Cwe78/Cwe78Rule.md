# CWE-78: Improper Neutralization of Special Elements used in an OS Command

This rule reports command execution calls for review. It checks
`exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()`,
`proc_open()`, and the backtick operator. It reports these calls even when
the command has no variable or external input. This gives the developer a
chance to review each command.

Finding one of these functions is not enough to establish CWE-78. The
developer must check if data from outside the application can change the
command or its arguments without correct neutralisation.

It also includes Laravel based input checks via the `request()` helper and input reads from `Illuminate\Http\Request` objects and their subclasses.

<!-- TOC -->
* [CWE-78: Improper Neutralization of Special Elements used in an OS Command](#cwe-78-improper-neutralization-of-special-elements-used-in-an-os-command)
  * [Rating](#rating)
  * [Ignore a finding](#ignore-a-finding)
  * [Scope for a first version](#scope-for-a-first-version)
  * [Known limitations](#known-limitations)
<!-- TOC -->

## Rating

The rule uses a rating that reflects how much the analysis knows about the
command and its input. The probability score is an estimate of confidence
in the finding. It is not a measured probability of an attack. Severity
describes the possible harm. Priority shows which findings to review first.

| Priority and severity | Probability | Context                                                                                                              |
|-----------------------|------------:|----------------------------------------------------------------------------------------------------------------------|
| Very high             |         95% | Direct external input is the full command, as in `exec($_GET['file'])`.                                              |
| High                  |         80% | Direct external input changes an argument in a command with known text.                                              |
| Medium                |         60% | The rule traces external input through a local variable assignment to the command.                                   |
| Low                   |         50% | The code calls a command sink, but the rule finds no direct external input. Review the command and its data sources. |

The rule gives a report for each command sink. It uses the rating table
when it finds request data. It gives a low rating when it does not find
request data. A low rating is a request to review the command, not proof
that the command is safe. Severity describes possible harm. Probability is
an estimate of confidence in the finding. It is not a measured probability
of an attack.

Unsafe PHP:

```php
exec('convert ' . $_GET['file'] . ' /tmp/output.png');
```

Protected input example:

```php
exec('convert ' . escapeshellarg($_GET['file']) . ' /tmp/output.png');
```

For `proc_open()`, use an argument array when the PHP version supports it.
This avoids shell parsing. The rule checks the executable value in this
form. It still reports the call for review:

```php
$process = proc_open(
    ['convert', $_GET['file'], '/tmp/output.png'],
    $descriptors,
    $pipes,
);
```

The rule checks values from `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`.
The [Laravel variant](../../LaravelRequestInput.md) also checks the `request()`
helper and input reads from Laravel request objects.
It follows simple local assignments in one function or method, as the
CWE-89 rule does. It reports every supported command sink. It does not
treat a value as safe only because it has a string type.

The rule recognizes `escapeshellarg()` around a value and does not treat
that value as direct request input. Use it for one shell argument. Do not
use it to build an executable name or a whole command. The rule does not
treat `escapeshellcmd()` as proof that user input is safe. It can stop some
shell syntax, but it does not stop a value from adding another argument.

## Ignore a finding

A developer can ignore a finding with an inline PHPStan ignore annotation and a clear
reason. A single word is not enough. The rule reports an ignore reason with
fewer than two words. Explain why the command or its arguments are safe in
this case.

For example:

```php
// @phpstan-ignore phpstanCwe.cwe78 (The command uses a fixed local file name.)
exec('tool fixed-file');
```

The rule should check that each ignore has a reason. The reason should give
enough detail for another developer to review the decision.

## Scope for a first version

The first version does not check these functions:

- `pcntl_exec()` starts another program, but it has a separate argument
  model. It needs a check that distinguishes the executable and its
  arguments.
- `pcntl_fork()` creates a process. It does not run a command by itself.
- `expect_popen()` runs commands through the Expect extension. Review it
  after the core sinks.
- `mail()` and `imap_open()` can depend on external programs or
  configuration. This rule does not infer that behaviour.

## Known limitations

- The rule follows simple assignments in source order in one function or
  method. It does not follow a value through a function or merge values
  from different branches or loops.
- It cannot prove that a command is safe. Review all values and command
  arguments by hand.
- It does not check every PHP function or extension that can start a
  process.
- It does not check operating system behaviour or the command's own argument
  parsing.
- `escapeshellarg()` must protect each untrusted shell argument in the
  correct position. It does not make an untrusted executable name safe.
- An argument array for `proc_open()` avoids shell parsing, but the
  program can still treat an argument as an option or otherwise unsafe
  input.

Full explanation: https://cwe.mitre.org/data/definitions/78.html
