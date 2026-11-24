<?php

function checkIncludeNames(string $unknown, string $selector, string $dynamicName, \Closure $filenameProvider): mixed
{
    include $_GET['page']; // Report: Request input supplies the filename.
    include_once __DIR__ . "/views/{$_GET['page']}.php"; // Report: Interpolation adds unchanged request input.

    $file = $_POST['page']; // No report: Assignment is not an inclusion.
    $copy = $file; // No report: The copy keeps the request input.
    $file = __DIR__ . '/home.php'; // No report: This fixed assignment replaces the input.
    require $copy; // Report: The copy keeps the earlier request input.

    $file = __DIR__ . '/views/'; // No report: This assignment is a fixed path.
    $file .= $_COOKIE['page']; // No report: This assignment adds request input.
    require_once $file; // Report: Concatenation assignment adds request input.

    include($_GET['page'] ?? __DIR__ . '/home.php'); // Report: The request value can supply the filename.
    include $_GET['page'] ?: __DIR__ . '/home.php'; // Report: The request value can supply the filename.
    require __DIR__ . '/views/' . basename($_GET['page']); // Report: basename() does not select an approved file.
    require __DIR__ . '/views/' . (int) $_GET['id'] . '.php'; // Report: A number can still select a file.

    include match ($_GET['page'] ?? '') { // No report: Input selects between fixed paths.
        'help' => __DIR__ . '/help.php',
        default => __DIR__ . '/home.php',
    };
    include match ($selector) { // Report: A match result contains request input.
        'help' => $_GET['page'],
        default => __DIR__ . '/home.php',
    };
    include match ($_GET['page']) { // No report: The selector does not supply the filename.
        'help' => __DIR__ . '/help.php',
        default => __DIR__ . '/home.php',
    };
    include basename(__DIR__ . '/home.php'); // No report: A fixed path stays fixed.
    include $_GET['page'] === 'help' ? __DIR__ . '/help.php' : __DIR__ . '/home.php'; // No report: Input selects between fixed paths.
    include basename($_GET['page']) . $_POST['suffix']; // Report: Unchanged input keeps the higher score.

    $file = $_GET['page']; // No report: Assignment is not an inclusion.
    $file = __DIR__ . '/home.php'; // No report: This fixed assignment replaces the input.
    include $file; // No report: The final value is a fixed path.
    include $unknown; // Report: The dynamic filename has no known request source.
    include $$dynamicName; // Report: The dynamic variable has no known request source.
    include $filenameProvider(); // Report: The function result has no known request source.
    include (fn () => $_GET['page'])(); // Report: The called arrow function returns request input.
    return include $_REQUEST['page']; // Report: The request value supplies the filename.
}

function includeInsideClosure(string $outsideLocal): void
{
    $file = $_GET['page']; // No report: Assignment is not an inclusion.
    $closure = static function () use ($file): void {
        include $file; // Report: The rule does not trace captured values.
        $local = $_POST['page']; // No report: Assignment facts stay in the closure.
        include $local; // Report: Request input supplies the filename.
    };
    include $outsideLocal; // Report: The rule does not share closure assignment facts.
}

function includeLaravelTemplate(\Illuminate\Http\Request $request): void
{
    include_once __DIR__ . '/views/' . $request->input('template'); // Report: Laravel request input supplies part of the filename.
}

function includeFromUnknownObject(stdClass $request): void
{
    include $request->input('template'); // Report: The filename is dynamic and its source is unknown.
}
