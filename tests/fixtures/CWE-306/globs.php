<?php

declare(strict_types=1);

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function post(string $uri, \Closure $action): self
        {
            return new self();
        }

        public function middleware(string $middleware): self
        {
            return $this;
        }
    }
}

namespace App\Models {
    class User
    {
        public function delete(): void
        {
        }

        public function deleteQuietly(): void
        {
        }
    }
}

namespace App\Models\Admin {
    class User extends \App\Models\User
    {
    }
}

namespace App\Models\Legacy\Archive {
    class User extends \App\Models\User
    {
    }
}

namespace {
    use Illuminate\Support\Facades\Route;

    Route::post('/direct', function (\App\Models\User $model): void {
        $model->delete();
    }); // Report: The direct class matches.
    Route::post('/nested', function (\App\Models\Admin\User $model): void {
        $model->delete();
    }); // Report: The child namespace matches.
    Route::post('/protected', function (\App\Models\Admin\User $model): void {
        $model->delete();
    })->middleware('auth:sanctum'); // No report: Authentication is required.
    Route::post('/excluded', function (\App\Models\Legacy\Archive\User $model): void {
        $model->delete();
    }); // No report: The recursive exclusion matches the receiver.
    Route::post('/other-method', function (\App\Models\User $model): void {
        $model->deleteQuietly();
    }); // No report: The method does not match.
}
