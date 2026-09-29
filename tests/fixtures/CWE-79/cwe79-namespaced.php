<?php

namespace Example;

function htmlspecialchars(string $text): string
{
    return $text; // This local function does not escape the input.
}

echo htmlspecialchars($_GET['name']); // Report: This call uses the local function.
echo \htmlspecialchars($_GET['name']); // No report: This call uses the PHP escape function.
