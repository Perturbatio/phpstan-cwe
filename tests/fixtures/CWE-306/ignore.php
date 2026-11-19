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

    // @phpstan-ignore phpstanCwe.cwe306.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (safe)
    Route::post('/short', function (): void {
        eraseAccounts();
    }); // Report: The annotation reason has only one word. The annotation does not suppress the route.

    // @phpstan-ignore phpstanCwe.cwe306.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    Route::post('/missing', function (): void {
        eraseAccounts();
    }); // Report: The annotation has no reason. The annotation does not suppress the route.

    // @phpstan-ignore phpstanCwe.cwe306.abc (External authentication)
    Route::post('/valid', function (): void {
        eraseAccounts();
    }); // Report: The annotation has no fingerprint. The annotation does not suppress the route.
}
