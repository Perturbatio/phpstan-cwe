<?php

$outside = $_GET['outside'];
$callback = function () use ($outside): void {
    echo $outside; // No report: Captured values are not tracked.
    $local = $_POST['name'];
    $copy = $local;
    echo $copy; // Report: Closure-local input reaches output.
    echo htmlspecialchars($local); // No report: The value is escaped.
    $copy = 'fixed';
    echo $copy; // No report: A fixed assignment replaces input.
    $copy .= $local;
    print $copy; // Report: Concatenation adds closure-local input.
    $nested = function (string $local): void {
        echo $local; // No report: The outer closure has a separate scope.
        $local = $_COOKIE['name'];
        echo $local; // Report: Nested closure-local input reaches output.
    };
    echo $nested; // No report: The closure body is not the assigned value.
    echo $local; // Report: The nested assignment does not change this value.
};
echo $local; // No report: Closure assignments do not reach the outer scope.
echo $callback; // No report: The closure body is not the assigned value.
$sibling = function (string $local): void {
    echo $local; // No report: A sibling closure has a separate scope.
    $local = 'fixed';
    echo $local; // No report: The value is fixed.
};
$arrow = fn () => print $_GET['name']; // Report: Direct input in an arrow function.
$arrowLocal = fn () => print ($arrowValue = $_GET['name']); // Report: Direct input in an arrow function.
echo $arrowValue; // No report: An arrow assignment does not reach the outer scope.
echo $arrow; // No report: The arrow body is not the assigned value.
echo (fn () => $_GET['name'])(); // Report: The arrow returns request input.
