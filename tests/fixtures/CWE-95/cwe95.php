<?php

function checkDynamicCode(): void
{
    eval($_GET['code']); // Report: GET input is passed to eval().
    $code = $_POST['code'];
    eval($code); // Report: POST input reaches eval() through a local assignment.
    eval('return 1 + 1;'); // Report: The rule reports fixed text at low probability.
    $unknownCode = getDynamicCode();
    eval($unknownCode); // Report: The rule cannot confirm that this value is static.
    $code = $_COOKIE['old'];
    $code = 'return 1;';
    eval($code); // Report: The new fixed assignment replaces the old request value.
    $data = $_GET['data']; // No report: This is not a dynamic evaluation sink.
    eval($_REQUEST['payload']['code']); // Report: Nested request input is passed to eval().
}

function getDynamicCode(): string
{
    return 'return 1;';
}
