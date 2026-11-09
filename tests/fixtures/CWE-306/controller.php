<?php

declare(strict_types=1);

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function delete(string $uri, array $action): self
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
    class Controller
    {
    }

    class UserController extends Controller
    {
        public function delete(): void
        {
        }
    }
}

namespace {
    use App\Http\Controllers\UserController;
    use Illuminate\Support\Facades\Route;

    Route::delete('/users/{user}', [UserController::class, 'delete']); // Report: The critical action has no authentication middleware.
    Route::delete('/private/users/{user}', [UserController::class, 'delete'])->middleware('auth:sanctum'); // No report: Sanctum authentication is required.
}
