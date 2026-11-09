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

namespace {
    use Illuminate\Support\Facades\Route;

    function eraseAccounts(): void
    {
    }

    Route::post('/erase', function (): void {
        eraseAccounts();
    }); // Report: This operation requires authentication.
    Route::post('/private', function (): void {
        eraseAccounts();
    })->middleware('auth'); // No report: Authentication is required.
    Route::post('/sanctum', function (): void {
        eraseAccounts();
    })->middleware('auth:sanctum'); // No report: Sanctum authentication is required.
    Route::post('/contact', function (): void {
    }); // No report: No critical operation is called.
}
