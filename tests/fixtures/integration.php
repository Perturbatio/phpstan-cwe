<?php

echo $_GET['name']; // Report: The HTML rule finds direct GET input.
$pdo = new PDO('sqlite::memory:'); // Give the SQL rule a known PDO value.
$pdo->query('SELECT * FROM users WHERE id = ' . $_POST['id']); // Report: The SQL rule finds direct POST input.
echo htmlspecialchars($_GET['name']); // No report: The HTML rule accepts escaped input.
