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

namespace App\Models\Issues {
    class ProductIssue extends \Illuminate\Database\Eloquent\Model
    {
    }
}

namespace App\Services {
    class Action
    {
        public function execute(): void
        {
        }
    }

    class Factory
    {
        public function createService(): Action
        {
            return new Action();
        }
    }
}

namespace {
    use App\Models\Issues\ProductIssue;
    use App\Services\Factory;
    use Illuminate\Database\Query\Builder;
    use Illuminate\Support\Facades\Route;

    Route::post('/eloquent-where', function (): void {
        ProductIssue::where('created_at', '<', '2020-01-01')->delete(); // Report with Larastan: The receiver is an Eloquent builder.
    });
    Route::post('/eloquent-query', function (): void {
        ProductIssue::query()->where('created_at', '<', '2020-01-01')->delete(); // Report: The receiver is a builder.
    });
    Route::post('/query', function (Builder $builder): void {
        $builder->where('created_at', '<', '2020-01-01')->delete(); // Report: The receiver is a query builder.
    });
    Route::post('/factory', function (Factory $factory): void {
        $factory->createService()->execute(); // Report: The returned action is configured.
    });
    Route::post('/protected', function (Factory $factory): void {
        $factory->createService()->execute(); // No report: Authentication is required.
    })->middleware('auth:sanctum');
    Route::post('/deferred', function (Factory $factory): void {
        $callback = fn () => $factory->createService()->execute(); // No report: The callback is not run.
    });
    Route::post('/facade', function (): void {
        \Illuminate\Support\Facades\DB::table('issues')->where('created_at', '<', '2020-01-01')->delete(); // Report: The receiver is a query builder.
    });
}

namespace App\Database {
    class IssueBuilder extends \Illuminate\Database\Eloquent\Builder
    {
    }
}

namespace {
    \Illuminate\Support\Facades\Route::post('/custom-builder', function (\App\Database\IssueBuilder $builder): void {
        $builder->where('created_at', '<', '2020-01-01')->where('status', '=', 'old')->delete(); // Report: The custom builder inherits delete.
    });
}
