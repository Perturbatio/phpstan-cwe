<?php

declare(strict_types=1);

namespace App\Http\Controllers {
    class UserController
    {
        public function delete(): void
        {
        }
    }
}

namespace {
    use App\Http\Controllers\UserController;
    use Illuminate\Support\Facades\Route;

    function eraseAccounts(): void
    {
    }

    Route::controller(UserController::class)->as('users.')->prefix('users')->group(function (): void {
        Route::post('/one', 'delete')->name('delete'); // Report: This action requires authentication.
        // @phpstan-ignore phpstanCwe.cwe306 (External gateway authenticates callers)
        Route::post('/ignored', 'delete'); // No report: This route has an ignore reason.
        Route::post('/two', 'delete'); // Report: The previous ignore annotation does not apply to this route.
        Route::post('/protected', 'delete')->middleware('auth:sanctum'); // No report: Authentication is required.
    });

    Route::controller(UserController::class)->middleware('auth')->group(function (): void {
        Route::post('/removed', 'delete')->withoutMiddleware('auth'); // Report: The route removes authentication.
    });

    Route::group(['prefix' => 'users'], function (): void {
        Route::post('/explicit', [UserController::class, 'delete']); // Report: This action requires authentication.
        Route::post('/closure', function (): void { // Report: The closure reaches a critical operation.
            eraseAccounts();
        });
        Route::post('/guarded', [UserController::class, 'delete'])->middleware('auth'); // No report: Authentication is required.
    });
}
