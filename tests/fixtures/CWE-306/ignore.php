<?php

namespace Illuminate\Support\Facades {
    class Route
    {
        public static function post(string $uri, \Closure $action): void
        {
        }
    }
}

namespace {
    use Illuminate\Support\Facades\Route;

    function eraseAccounts(): void
    {
    }

    // @phpstan-ignore phpstanCwe.cwe306 (safe)
    Route::post('/short', function (): void {
        eraseAccounts();
    }); // Report: The ignore reason has only one word.

    // @phpstan-ignore phpstanCwe.cwe306
    Route::post('/missing', function (): void {
        eraseAccounts();
    }); // Report: The ignore has no reason.

    // @phpstan-ignore phpstanCwe.cwe306 (External authentication)
    Route::post('/valid', function (): void {
        eraseAccounts();
    }); // No report: The ignore has a reason with two words.
}
