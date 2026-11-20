<?php

echo (function (): string {
    return $_GET['name'] ?? '';
})(); // Report: The closure returns request input.
$getName = fn (): string => $_GET['name'] ?? '';
echo $getName(); // Report: The arrow returns request input.
$name = $_GET['name'] ?? '';
echo (fn (): string => $name)(); // Report: The arrow captures request input.
echo (fn (): string => htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8'))(); // No report: The returned value is escaped.
echo htmlspecialchars((fn (): string => $_GET['name'] ?? '')(), ENT_QUOTES, 'UTF-8'); // No report: The output is escaped.
$safe = fn () => htmlspecialchars($_GET['name']);
echo $safe(); // No report: The returned value is escaped.
echo $getName; // No report: The callback is not called.
$copy = $getName;
$getName = fn () => 'fixed';
echo $copy(); // Report: The copy keeps the original callback.
echo $getName(); // No report: The callback was replaced.
$name = 'fixed';
echo (fn () => $name)(); // No report: The captured value is fixed.
$name = $_POST['name'];
$captured = fn () => $name;
$name = 'fixed';
echo $captured(); // Report: The arrow keeps the earlier captured value.
echo (fn (string $name) => $name)('fixed'); // No report: The parameter does not capture the outer value.
echo htmlspecialchars($_GET['name'], ENT_NOQUOTES, 'UTF-8'); // Report: The flags do not escape quotes.
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'invalid-encoding'); // Report: The encoding is not accepted.
echo htmlspecialchars(string: $_GET['name'], flags: ENT_QUOTES, encoding: 'UTF-8'); // No report: Named arguments use accepted flags and encoding.
echo htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'utf-8'); // No report: These flags escape quotes.
echo htmlspecialchars($_GET['name'], ENT_COMPAT, 'UTF-8'); // Report: Single quotes are not escaped.
$saved = $captured;
$captured = fn () => 'fixed';
echo $saved(); // Report: A copied arrow retains its captured input.
echo $captured(); // No report: The arrow was replaced.
$localName = $_GET['name'];
$escapedArrow = fn () => htmlspecialchars($localName, ENT_QUOTES, 'UTF-8');
echo $escapedArrow(); // No report: The captured value is escaped.
$shadow = fn ($localName) => $localName;
echo $shadow('fixed'); // No report: A parameter does not capture an outer variable.
echo (fn ($localName) => $localName)('fixed'); // No report: The parameter does not capture the outer value.
echo (fn ($localName) => $localName)($_GET['name']); // Report: Request input is passed to the arrow.
$unsafe = fn () => $_GET['name'];
$callsUnsafe = fn () => $unsafe();
echo $callsUnsafe(); // Report: The captured callback returns request input.
echo (fn () => $unsafe())(); // Report: The captured callback returns request input.
$takesCallback = fn ($unsafe) => $unsafe();
echo $takesCallback(fn () => 'fixed'); // No report: The parameter does not capture the outer callback.
