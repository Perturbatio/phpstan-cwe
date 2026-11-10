<?php

declare(strict_types=1);

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function get(string $uri, \Closure $action): self
        {
            return new self();
        }

        public function middleware(string $middleware): self
        {
            return $this;
        }
    }
}

namespace App\Http\Controllers {
    class UserController
    {
        public function delete(): void
        {
        }
    }
}

namespace {
    use App\Http\Controllers\UserController as DeleteAction;
    use Illuminate\Support\Facades\Route;

    Route::get('/public', function (): void { // Report: A local object reaches a critical operation.
        $action = new DeleteAction();
        $action->delete();
    });

    Route::get('/private', function (): void { // No report: Sanctum authentication is required.
        $action = new DeleteAction();
        $action->delete();
    })->middleware('auth:sanctum');

    Route::get('/container', function (): void { // Report: The requested class has a configured critical method.
        $action = app(DeleteAction::class);
        $action->delete();
    });

    Route::get('/container-make', function (): void { // Report: The requested class has a configured critical method.
        $action = app()->make(DeleteAction::class);
        $action->delete();
    });

    Route::get('/private-container', function (): void { // No report: Sanctum authentication is required.
        $action = app(DeleteAction::class);
        $action->delete();
    })->middleware('auth:sanctum');

    Route::get('/private-container-make', function (): void { // No report: Sanctum authentication is required.
        $action = app()->make(DeleteAction::class);
        $action->delete();
    })->middleware('auth:sanctum');
}
