<?php

function checkCommands(array $descriptors, array &$pipes): void
{
    exec($_GET['command']); // Report: GET input is the full command.
    exec('tool ' . $_GET['argument']); // Report: GET input changes an argument in known command text.
    $command = $_POST['command'];
    system($command); // Report: POST input reaches the command through an assignment.
    $command = 'tool';
    $command .= $_REQUEST['argument'];
    passthru($command); // Report: REQUEST input reaches the command through a concatenation assignment.
    exec('tool fixed'); // Report: The sink needs review when no external input is found.
    shell_exec('tool ' . escapeshellarg($_COOKIE['argument'])); // Report: The sink needs review even when the value is escaped.
    passthru('tool ' . $_GET['argument']); // Report: GET input changes an argument.
    popen('tool ' . $_POST['argument'], 'r'); // Report: POST input changes an argument.
    proc_open('tool ' . $_REQUEST['argument'], $descriptors, $pipes); // Report: REQUEST input changes an argument.
    proc_open(['tool', $_GET['argument']], $descriptors, $pipes); // Report: The safe argument array still needs review.
    // @phpstan-ignore backtick.deprecated
    $output = `tool {$command}`; // Report: Assigned request input reaches a backtick command.
    exec(command: $_GET['named']); // Report: Named command input is the full command.
}
