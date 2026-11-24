<?php

namespace LaravelPaths {
    use Illuminate\Support\Facades\Route as LaravelRoute;

    function paths(string $unknown): void
    {
        require \base_path('routes/channels.php'); // No report: The argument is fixed.
        include \app_path($_GET['page']); // Report: Input changes the path.
        include \resource_path($unknown); // Report: The argument is unknown.
        include \storage_path('cache/file.php'); // No report: The argument is fixed.
        include custom_path('home.php'); // Report: The function is not known.
        include app_path('home.php'); // Report: The local helper is not the Laravel helper.

        $files = [\app_path('a.php'), \app_path('b.php')];
        foreach ($files as $file) {
            include $file; // No report: The list contains fixed paths.
        }

        $files[] = $_GET['page'];
        foreach ($files as $file) {
            include $file; // Report: Input was added to the list.
        }

        $files = [\app_path('a.php')];
        array_push($files, $_POST['page']);
        foreach ($files as $file) {
            include $file; // Report: A call can change the list.
        }

        foreach ($_GET['files'] as $file) {
            include $file; // Report: The list comes from request input.
        }
    }

    function app_path(string $path): string
    {
        return $_GET['path'] . $path;
    }

    LaravelRoute::get('/pages/{page}', function (string $page): void {
        include $page; // Report: The route supplies the value.
        $page = __FILE__;
        include $page; // No report: The value was replaced.
    });

    LaravelRoute::get('/pages/{page}', fn (string $page) => include \app_path($page)); // Report: The route supplies the value.
    LaravelRoute::get('/fixed', function (string $page = 'fixed.php'): void {
        include $page; // Report: This is not a route parameter.
    });

    OtherRoute::get('/pages/{page}', function (string $page): void {
        include $page; // Report: This is not a Laravel route.
    });

    function custom_path(string $path): string
    {
        return $path;
    }

    class OtherRoute
    {
        public static function get(string $uri, callable $action): void
        {
        }
    }

    function listChanges(): void
    {
        $files = [\app_path('a.php')];
        $files += ['unsafe' => $_GET['file']];
        foreach ($files as $file) {
            include $file; // Report: Input can be added to the list.
        }

        $files = [\app_path('a.php')];
        changeList($files);
        foreach ($files as $file) {
            include $file; // Report: A call can change the list.
        }
    }

    function changeList(array &$files): void
    {
        $files[] = $_GET['file'];
    }

    LaravelRoute::get('/{name}', function (string $name): void {
        (function (string $name): void {
            include $name; // Report: The nested parameter is not a route parameter.
        })(__FILE__);
        include (int) $name; // Report: The cast changes the route parameter.
    });

    function listReferences(): void
    {
        $files = [\app_path('a.php')];
        $alias = &$files;
        $alias[] = $_GET['file'];
        foreach ($files as $file) {
            include $file; // Report: The list can change through a reference.
        }
    }

    function changeListItem(): void
    {
        $files = [\app_path('a.php')];
        $files[0] .= $_GET['suffix'];
        foreach ($files as $file) {
            include $file; // Report: Input changes an item.
        }
    }
}
