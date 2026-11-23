<?php

namespace App\Providers {
    use Illuminate\Support\Facades\Broadcast;
    use Illuminate\Support\ServiceProvider;

    class BroadcastServiceProvider extends ServiceProvider
    {
        public function boot(): void
        {
            Broadcast::routes();

            require base_path('routes/channels.php'); // No report: The helper receives a fixed path.
        }

        public function register(): void
        {
            $helpers = [
                app_path('Helpers/ArrayHelpers.php'),
                app_path('Helpers/SpreadsheetHelpers.php'),
                app_path('Helpers/TranslationHelpers.php'),
                app_path('Helpers/Date.php'),
            ];
            foreach ($helpers as $helper) {
                if (file_exists($helper)) {
                    require_once $helper; // No report: Each list item is a fixed path.
                }
            }
        }
    }
}

namespace App\Http\Controllers {
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Storage;

    function loadTemplate(Request $request): mixed
    {
        $section = $request->input('section');

        return require resource_path("sections/{$section}.php"); // Report: Request input reaches the filename through a function.
    }

    function loadMapper(Request $request): mixed
    {
        $mapper = $request->query('mapper');
        $path = Storage::disk('mappers')->path($mapper);

        return include $path; // Report: Request input reaches the filename through a method.
    }

    function loadOtherFiles(Request $request): void
    {
        include $request->input('template'); // Report: Request input supplies the filename.
        include basename($request->input('template')); // Report: basename does not select an approved file.
        include (int) $request->input('id'); // Report: A number can still select a file.
        include match ($request->input('page')) { // No report: Input selects between fixed paths.
            'help' => __DIR__ . '/help.php',
            default => __DIR__ . '/home.php',
        };
        require __DIR__ . '/home.php'; // No report: The filename is fixed.
    }
}

namespace App\Routes {
    use Illuminate\Support\Facades\Route;

    Route::get('/plugins/{plugin}/run', function (string $plugin): void {
        $file = app_path("Plugins/{$plugin}/handler.php");

        if (is_file($file)) {
            require_once $file; // Report: The route parameter changes the path.
        }
    });
}
