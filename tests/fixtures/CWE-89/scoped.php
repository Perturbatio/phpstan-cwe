<?php

class Repo
{
    public function find(mysqli $mysqli): void
    {
        MYSQLI_QUERY($mysqli, 'SELECT * FROM users WHERE id = ' . $_GET['id']); // Report: Method scope.
    }
}

function findUser(mysqli $mysqli): void
{
    mysqli_query($mysqli, 'SELECT * FROM users WHERE id = ' . $_GET['id']); // Report: Function scope.
}

mysqli_query(new mysqli(), 'SELECT * FROM users WHERE id = ' . $_GET['id']); // Report: File scope.
