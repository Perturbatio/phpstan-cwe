<?php

echo '<p>' . ($_GET['message'] ?? '') . '</p>'; // Report: Request input reaches HTML.
$message = (string) ($_GET['message'] ?? '');
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>'; // No report: The value is escaped.
echo '<input type="text" value=' . ($_GET['query'] ?? '') . '>'; // Report: The attribute is not escaped.
$query = (string) ($_GET['query'] ?? '');
echo '<input type="text" value="' . htmlspecialchars($query, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">'; // No report: The value is escaped.
$userLabel = $_GET['label'] ?? '';
echo '<script>const userLabel = "' . $userLabel . '";</script>'; // Report: Request input reaches output.
$safeJson = json_encode(
    (string) ($_GET['label'] ?? ''),
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
);
echo '<script>const userLabel = ' . htmlspecialchars((string) $safeJson, ENT_NOQUOTES, 'UTF-8') . ';</script>'; // Report: The rule does not check JavaScript encoding.
echo '<a href="' . ($_GET['next'] ?? '') . '">Continue</a>'; // Report: The URL is not escaped.
$rawNext = (string) ($_GET['next'] ?? '');
$scheme = strtolower((string) parse_url($rawNext, PHP_URL_SCHEME));
$safeUrl = in_array($scheme, ['http', 'https'], true) ? $rawNext : '/default-page';
echo '<a href="' . htmlspecialchars($safeUrl, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Continue</a>'; // No report: The value is escaped.
