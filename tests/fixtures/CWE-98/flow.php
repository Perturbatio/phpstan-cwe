<?php

function checkIncludeFlow(string $unknown, bool $choice): void
{
    $raw = $_GET['page']; // No report: Assignment is not an inclusion.
    $transformed = basename($raw); // No report: Assignment is not an inclusion.
    $number = (int) $raw; // No report: Assignment is not an inclusion.
    $copy = $transformed; // No report: Assignment is not an inclusion.
    $unknownCopy = $unknown; // No report: Assignment is not an inclusion.
    $fixed = dirname('/pages/home.php'); // No report: Assignment is not an inclusion.

    include $raw; // Report: The request value is unchanged.
    include basename($raw); // Report: The function changes the request value.
    include (float) $raw; // Report: The numeric cast changes the request value.
    include $transformed; // Report: The function changes the request value.
    include $number; // Report: The numeric cast changes the request value.
    include $copy; // Report: The copy keeps the transformed value.
    include basename($number); // Report: The numeric cast keeps the lower score.
    include (int) $transformed; // Report: The numeric cast lowers the score.
    include $transformed . $raw; // Report: The unchanged value gives the higher score.
    include $unknownCopy; // Report: The value has no known request source.
    include $unknown . $raw; // Report: The known request value gives the score.
    include $fixed; // No report: The value is a fixed path.
    include $choice ? $fixed : '/pages/help.php'; // No report: Each result is fixed.
    include $choice ? $number : '/pages/help.php'; // Report: One result uses numeric input.
    include $fixed ?: $raw; // Report: The alternative uses request input.
    include dirname('/pages/home.php'); // No report: The function receives a fixed path.
    include makePath('/pages/home.php'); // Report: The function result is unknown.
}
