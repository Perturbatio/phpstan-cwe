<?php

declare(strict_types=1);

// Larastan needs a framework version when the fixture has no Laravel application.
define('LARAVEL_VERSION', Illuminate\Foundation\Application::VERSION);

$application = new Illuminate\Foundation\Application(dirname(__DIR__));
$application->instance('config', new Illuminate\Config\Repository([
    'database' => [
        'default' => 'sqlite',
        'connections' => ['sqlite' => ['driver' => 'sqlite', 'database' => ':memory:']],
    ],
]));
$application->register(Illuminate\Database\DatabaseServiceProvider::class);
