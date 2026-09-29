<?php

echo $_GET['name']; // Report: GET input goes to HTML without an escape call.
echo htmlspecialchars($_GET['name']); // No report: This call escapes the GET input.
print $_POST['comment']; // Report: PRINT sends POST input to HTML.
echo 'Hello ', $_COOKIE['session']; // Report: The second ECHO value is COOKIE input.
echo (int) $_GET['id']; // No report: The cast changes the input to a number.
echo htmlspecialchars($_GET['name']) . $_REQUEST['other']; // Report: The second value is not escaped.
$alias = $_GET['name']; // The rule does not follow input after assignment.
echo $alias; // No report: The rule does not follow the assigned value.
