<?php

$outside = $_GET['name'];
echo (fn () => $_GET['name'])(); // Report: The arrow returns request input.
print (function () { return $_POST['name']; })(); // Report: The closure returns request input.
$value = (fn () => $_COOKIE['name'])();
echo $value; // Report: The returned input is assigned before output.
echo (fn () => htmlspecialchars($_GET['name']))(); // No report: The arrow escapes its return value.
echo htmlspecialchars((fn () => $_GET['name'])()); // No report: The output is escaped.
echo (function () { return (int) $_GET['name']; })(); // No report: The return value is numeric.
echo (function () { $unused = $_GET['name']; return 'fixed'; })(); // No report: Input is not returned.
echo (function () { return; })(); // No report: There is no return value.
echo (function () { $callback = fn () => $_GET['name']; return 'fixed'; })(); // No report: The nested callback is not called.
echo (function () use ($outside) { return $outside; })(); // No report: Captured values are not tracked.
echo (fn () => $outside)(); // Report: The arrow captures request input.
echo (function (string $outside) { return $outside; })('fixed'); // No report: The parameter is not the outer value.
echo (fn () => print $_GET['name'])(); // Report: The inner print sends request input to HTML.
echo (function () { if (random_int(0, 1)) { return $_GET['name']; } return 'fixed'; })(); // Report: A return expression has request input.
echo (fn () => (fn () => $_GET['name'])())(); // Report: A nested call returns request input.
echo (fn () => 'fixed')(...); // No report: This creates a first-class callable.
