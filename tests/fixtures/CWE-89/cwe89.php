<?php

function checkQueries(PDO $pdo, mysqli $mysqli): void
{
    $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']); // Report: GET input changes the PDO query text.
    $pdo->prepare("SELECT * FROM users WHERE id = " . $_POST['id']); // Report: PREPARE cannot protect input already in the query text.
    $pdo->exec('DELETE FROM users WHERE id = ' . (int) $_GET['id']); // No report: The cast changes the input to a number.
    $pdo->prepare('SELECT * FROM users WHERE id = ?')->execute([$_GET['id']]); // No report: The input is a bound value.
    $mysqli->query('SELECT * FROM users WHERE id = ' . $_COOKIE['id']); // Report: COOKIE input changes the mysqli query text.
    mysqli_query($mysqli, 'SELECT * FROM users WHERE id = ' . $_REQUEST['id']); // Report: The mysqli function gets input in the query text.
    $query = 'SELECT * FROM users WHERE id = ' . $_GET['id']; // The rule does not follow input after assignment.
    $pdo->query($query); // No report: The rule does not follow the assigned value.
    $pdo->query(query: 'SELECT * FROM users WHERE id = ' . $_GET['id']); // Report: The named query argument has GET input.
    mysqli_query(query: 'SELECT * FROM users WHERE id = ' . $_POST['id'], mysql: $mysqli); // Report: The named query argument has POST input.
}
