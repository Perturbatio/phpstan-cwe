<?php

declare(strict_types=1);

use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Illuminate\Routing\Router;
use Perturbatio\PhpstanCwe\Rules\Cwe306\LaravelAuthenticationScanner;
use PhpParser\ParserFactory;

covers(LaravelAuthenticationScanner::class);

class GroupTestController
{
    public function __invoke(): void
    {
    }
}

class OtherGroupTestController
{
    public function __invoke(): void
    {
    }
}

function scanControllerGroups(string $source, ?array $globalMiddleware, array $aliases, array $operations): array
{
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $source);

    return (new LaravelAuthenticationScanner($operations, $aliases, $globalMiddleware))->scan(['routes.php' => $nodes]);
}

it('confirms Laravel controller group registration and middleware inheritance', function (): void {
    $router = new Router(new Dispatcher(), new Container());
    $router->controller(GroupTestController::class)->middleware('auth')->group(function (Router $router): void {
        $router->post('outer', 'store');
        $router->controller(OtherGroupTestController::class)->withoutMiddleware('auth')->group(function (Router $router): void {
            $router->post('inner', 'store');
        });
        $router->post('array', [OtherGroupTestController::class, 'store']);
        $router->post('at', OtherGroupTestController::class . '@store');
        $router->post('invoke', OtherGroupTestController::class);
        $router->post('closure', fn () => null);
        $router->post('sibling', 'store')->withoutMiddleware('auth');
    });
    $routes = $router->getRoutes()->getRoutes();

    expect(array_map(fn ($route) => $route->getActionName(), $routes))->toBe([
        GroupTestController::class . '@store',
        OtherGroupTestController::class . '@store',
        OtherGroupTestController::class . '@store',
        OtherGroupTestController::class . '@store',
        OtherGroupTestController::class,
        GroupTestController::class,
        GroupTestController::class . '@store',
    ])->and($routes[5]->getAction('uses'))->toBeInstanceOf(Closure::class)
        ->and($routes[0]->gatherMiddleware())->toContain('auth')
        ->and($routes[1]->excludedMiddleware())->toContain('auth')
        ->and($routes[6]->excludedMiddleware())->toContain('auth')
        ->and($router->resolveMiddleware($routes[1]->gatherMiddleware(), $routes[1]->excludedMiddleware()))->toBe([]);
});

it('resolves controller groups without changing explicit handlers', function (string $group, array $expected): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
use App\ProductController as Product;
class ProductController { public function store() {} public function __invoke() {} }
class OtherController { public function store() {} public function __invoke() {} }
GROUP
PHP;
    $reports = scanControllerGroups(str_replace('GROUP', $group, $source), [], [], [
        'App\ProductController::store', 'App\OtherController::store', 'App\OtherController::__invoke', 'eraseAccounts',
    ]);

    expect(array_column($reports, 'operation'))->toBe($expected);
})->with([
    ["Route::controller(Product::class)->as('products.')->prefix('products')->group(function () { Route::post('/', 'store')->name('store'); });", ['App\ProductController::store']],
    ["Route::controller(\App\ProductController::class)->group(function () { Route::post('/', 'store'); });", ['App\ProductController::store']],
    ["Route::controller('App\\\\ProductController')->group(function () { Route::post('/', 'store'); });", ['App\ProductController::store']],
    ["Route::group(['controller' => Product::class], function () { Route::post('/', 'store'); });", ['App\ProductController::store']],
    ["Route::controller(Product::class)->group(function () { Route::post('/', [OtherController::class, 'store']); Route::post('/a', 'App\\\\OtherController@store'); Route::post('/b', OtherController::class); });", ['App\OtherController::store', 'App\OtherController::store', 'App\OtherController::__invoke']],
    ["Route::controller(Product::class)->group(function () { Route::post('/', 'App\\\\OtherController'); });", ['App\OtherController::__invoke']],
    ["Route::controller(Product::class)->group(function () { Route::post('/', '\\\\App\\\\OtherController'); });", ['App\OtherController::__invoke']],
    ["Route::controller(Product::class)->group(function () { Route::post('/', fn () => eraseAccounts()); Route::post('/b', function () { eraseAccounts(); }); });", ['eraseAccounts', 'eraseAccounts']],
    ["Route::post('/', 'store');", []],
    ["Route::controller(\$controller)->group(function () { Route::post('/', 'store'); });", []],
    ["Route::controller(Product::class)->group(function () { Route::post('/', \$method); });", []],
    ["Route::controller(Product::class)->group(function () { Route::group(['controller' => \$unknown], function () { Route::post('/', 'store'); }); });", []],
    ["Route::controller(Product::class)->group(function () { Route::group([\$attribute => 'unknown'], function () { Route::post('/', 'store'); }); });", []],
    ["Route::controller(Product::class)->group(function () { Route::namespace('Other')->group(function () { Route::post('/', 'store'); }); });", []],
    ["Route::namespace('Other')->controller(Product::class)->group(function () { Route::post('/', 'store'); });", []],
    ["Route::group(['namespace' => 'Other', 'controller' => Product::class], function () { Route::post('/', 'store'); });", []],
    ["Route::namespace('Other')->group(function () { Route::controller(Product::class)->group(function () { Route::post('/', 'store'); }); });", []],
    ["Route::controller(Product::class)->{\$method}()->controller(Product::class)->group(function () { Route::post('/', 'store'); });", []],
    ["Route::controller(Product::UNKNOWN)->group(function () { Route::post('/', 'store'); });", []],
    ["Route::controller('\\\\App\\\\ProductController')->group(function () { Route::post('/', 'store'); });", ['App\ProductController::store']],
    ["Route::controller('invalid class')->group(function () { Route::post('/', 'store'); });", []],
    ["Route::controller(['App\\\\ProductController'])->group(function () { Route::post('/', 'store'); });", []],
]);

it('does not resolve special controller names as classes', function (string $controller): void {
    $source = "use Illuminate\Support\Facades\Route; Route::controller('$controller')->group(function () { Route::post('/', 'store'); });";
    expect(scanControllerGroups($source, [], [], [strtolower($controller) . '::store']))->toBe([]);
})->with(['SELF', 'STATIC', 'PARENT']);

it('resolves a leading namespace separator before checking a controller body', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController { public function store() {} }
Route::controller('\App\ProductController')->group(function () { Route::post('/', 'store'); });
PHP;
    $reports = scanControllerGroups($source, [], [], ['App\ProductController::store']);
    expect($reports)->toHaveCount(1)->and($reports[0]['probability'])->toBe(100);
});

it('rejects invalid grouped method strings before they become symbols', function (string $handler, ?string $controller): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse('<?php ' . var_export($handler, true) . ';');
    $resolve = new ReflectionMethod(LaravelAuthenticationScanner::class, 'handlerSymbol');
    expect($resolve->invoke(new LaravelAuthenticationScanner(), $nodes[0]->expr, ['class' => $controller]))->toBeNull();
})->with([
    ['App\MissingController', 'App\ProductController'],
    ['store', null],
]);

it('keeps literal class handlers separate from grouped method strings', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController {}
Route::controller(ProductController::class)->group(function () {
    Route::post('/invoke', MissingController::class);
    Route::post('/invalid', 'App\MissingController');
});
PHP;
    $reports = scanControllerGroups($source, [], [], ['App\MissingController::__invoke']);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\MissingController::__invoke')
        ->and($reports[0]['line'])->toBe(5);
});

it('keeps nested controller contexts isolated including unknown overrides', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController { public function store() {} }
class OtherController { public function store() {} }
Route::controller(ProductController::class)->group(function () {
    Route::post('/one', 'store');
    Route::controller(OtherController::class)->group(function () { Route::post('/two', 'store'); });
    Route::controller($dynamic)->group(function () { Route::post('/unknown', 'store'); });
    Route::post('/three', 'store');
});
PHP;
    $reports = scanControllerGroups($source, [], [], ['App\**\*Controller::store']);
    expect(array_column($reports, 'operation'))->toBe(['App\ProductController::store', 'App\OtherController::store', 'App\ProductController::store'])
        ->and(array_column($reports, 'line'))->toBe([6, 7, 9])
        ->and(array_column($reports, 'probability'))->toBe([100, 100, 100]);
});

it('keeps grouped middleware and exclusions on the correct routes', function (string $outer, string $inner, ?array $global, array $aliases, ?int $probability): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; class ProductController { public function store() {} } '
        . "Route::controller(ProductController::class){$outer}->group(function () { Route::post('/', 'store'){$inner}; });";
    $reports = scanControllerGroups($source, $global, $aliases, ['App\ProductController::store']);
    expect($reports)->toHaveCount($probability === null ? 0 : 1);
    if ($probability !== null) {
        expect($reports[0]['probability'])->toBe($probability);
    }
})->with([
    ['', '', [], [], 100],
    ['->middleware("auth")', '', [], [], null],
    ['->middleware("auth:sanctum")', '', [], [], null],
    ['', '->middleware("auth")', [], [], null],
    ['->middleware("members")', '', [], ['members' => 'Illuminate\Auth\Middleware\Authenticate'], null],
    ['->middleware("custom")', '', [], [], 60],
    ['->middleware($dynamic)', '', [], [], 60],
    ['->middleware("auth")', '->withoutMiddleware("auth")', [], [], 100],
    ['->middleware("auth")->withoutMiddleware("auth")', '', [], [], 100],
    ['->middleware("auth")->withoutMiddleware("auth")', '', ['auth'], [], null],
    ['->middleware("auth:sanctum")', '->withoutMiddleware("auth:api")', [], [], null],
    ['->middleware("auth:sanctum")', '->withoutMiddleware("auth:sanctum")', [], [], 100],
    ['->middleware("auth:sanctum:extra")', '->withoutMiddleware("auth:sanctum")', [], [], null],
    ['->middleware("auth:sanctum")', '->withoutMiddleware("auth:sanctum:extra")', [], [], null],
    ['->middleware("auth")', '->withoutMiddleware("auth:api")', [], [], null],
    ['->middleware("auth")->withoutMiddleware($unknown)', '', [], [], 60],
    ['', '', null, [], 60],
]);

it('matches grouped and explicit controller routes with the same confidence', function (string $middleware): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; class ProductController { public function store() { \eraseAccounts(); } } '
        . "Route::controller(ProductController::class){$middleware}->group(function () { Route::post('/group', 'store'); }); "
        . "Route::post('/explicit', [ProductController::class, 'store']){$middleware};";
    $reports = scanControllerGroups($source, [], [], ['eraseAccounts']);

    expect(array_column($reports, 'operation'))->toBe(['eraseAccounts', 'eraseAccounts'])
        ->and(array_column($reports, 'probability'))->toBe([$middleware === '' ? 100 : 60, $middleware === '' ? 100 : 60]);
})->with(['', '->middleware("unknown")']);

it('inherits group attribute exclusions without affecting sibling groups', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController { public function store() {} }
Route::middleware('auth')->controller(ProductController::class)->group(function () {
    Route::group(['excluded_middleware' => 'auth'], function () {
        Route::group(['prefix' => 'nested'], function () { Route::post('/unprotected', 'store'); });
    });
    Route::post('/protected', 'store');
});
PHP;
    $reports = scanControllerGroups($source, [], [], ['App\ProductController::store']);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100)
        ->and($reports[0]['line'])->toBe(6);
});

it('preserves unknown exclusions and earlier exclusions in group attributes', function (string $attributes, int $probability): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController {
    public function __construct() { $this->middleware('auth'); }
    public function store() {}
}
Route::controller(ProductController::class)->withoutMiddleware('auth')->group(function () {
    Route::group(ATTRIBUTES, function () { Route::post('/', 'store'); });
});
PHP;
    $reports = scanControllerGroups(str_replace('ATTRIBUTES', $attributes, $source), [], [], ['App\ProductController::store']);
    expect($reports)->toHaveCount(1)->and($reports[0]['probability'])->toBe($probability);
})->with([
    ["['excluded_middleware' => []]", 100],
    ["['excluded_middleware' => \$unknown]", 60],
    ["['other' => 'value']", 60],
]);

it('keeps controller middleware unknown when an attribute key is dynamic', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController {
    public function __construct() { $this->middleware('auth'); }
    public function store() {}
}
Route::group([$unknown => 'value'], function () { Route::post('/', [ProductController::class, 'store']); });
PHP;
    $reports = scanControllerGroups($source, [], [], ['App\ProductController::store']);
    expect($reports)->toHaveCount(1)->and($reports[0]['probability'])->toBe(60);
});

it('keeps controller authentication when a group has a known unrelated attribute', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController {
    public function __construct() { $this->middleware('auth'); }
    public function store() {}
}
Route::group(['other' => 'value'], function () { Route::post('/', [ProductController::class, 'store']); });
PHP;
    expect(scanControllerGroups($source, [], [], ['App\ProductController::store']))->toBe([]);
});

it('checks explicit controller and closure handlers in ordinary route groups', function (string $middleware, array $expected): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController { public function store() {} }
Route::group(['prefix' => 'products', MIDDLEWARE], function () {
    Route::post('/one', [ProductController::class, 'store']);
    Route::post('/two', function () { \eraseAccounts(); });
    Route::post('/three', [ProductController::class, 'store'])->withoutMiddleware('auth');
    Route::post('/four', fn () => \eraseAccounts())->middleware('auth');
});
PHP;
    $reports = scanControllerGroups(str_replace('MIDDLEWARE', $middleware, $source), [], [], [
        'App\ProductController::store', 'eraseAccounts',
    ]);

    expect(array_column($reports, 'operation'))->toBe($expected);
})->with([
    ["'middleware' => []", ['App\ProductController::store', 'eraseAccounts', 'App\ProductController::store']],
    ["'middleware' => 'auth'", ['App\ProductController::store']],
    ["'middleware' => 'custom'", ['App\ProductController::store', 'eraseAccounts', 'App\ProductController::store']],
]);

it('preserves matching and authentication behaviour for grouped actions', function (string $controller, array $operations, ?string $expected, int $probability): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
class Request extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return $this->user() !== null; }
}
class BaseController { public function store() { \eraseAccounts(); } }
class ProductController extends BaseController { CONTROLLER }
Route::controller(ProductController::class)->group(function () { Route::post('/', 'store'); });
PHP;
    $reports = scanControllerGroups(str_replace('CONTROLLER', $controller, $source), [], [], $operations);
    expect(array_column($reports, 'operation'))->toBe($expected === null ? [] : [$expected]);
    if ($expected !== null) {
        expect($reports[0]['probability'])->toBe($probability);
    }
})->with([
    ['', ['App\BaseController::store'], 'App\BaseController::store', 100],
    ['', ['App\**\*Controller::store', '!App\BaseController::*'], null, 0],
    ['public function store() {}', ['App\BaseController::store'], null, 0],
    ['', ['eraseAccounts'], 'eraseAccounts', 100],
    ['public function store() { if (!Auth::check()) { exit; } \eraseAccounts(); }', ['eraseAccounts'], null, 0],
    ['public function store() { if (!Auth::check()) { exit; } Auth::logout(); \eraseAccounts(); }', ['eraseAccounts'], 'eraseAccounts', 100],
    ['public function store(Request $request) { \eraseAccounts(); }', ['eraseAccounts'], null, 0],
    ['public function __construct() { $this->middleware("auth"); }', ['eraseAccounts'], null, 0],
    ['public function store() { $callback = fn () => \eraseAccounts(); }', ['eraseAccounts'], null, 0],
]);

it('keeps route and operation locations separate across files', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $routes = $parser->parse(<<<'PHP'
<?php
use Illuminate\Support\Facades\Route;
Route::controller(\App\ProductController::class)->group(function () {
    Route::post('/one', 'store'); Route::post('/two', 'store');
});
PHP);
    $controller = $parser->parse(<<<'PHP'
<?php
namespace App;
class ProductController {
    public function store() {
        \eraseAccounts();
        \eraseAccounts();
    }
}
PHP);
    $reports = (new LaravelAuthenticationScanner(['eraseAccounts'], [], []))->scan([
        'routes.php' => $routes,
        'controller.php' => $controller,
    ]);

    expect(array_column($reports, 'file'))->toBe(['routes.php', 'routes.php'])
        ->and(array_column($reports, 'line'))->toBe([4, 4])
        ->and(array_column($reports, 'operationLine'))->toBe([5, 5]);
});

it('keeps collected chained call facts in grouped controller bodies', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse(<<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
class ProductController { public function store() { factory()->execute(); } }
Route::controller(ProductController::class)->group(function () { Route::post('/', 'store'); });
PHP);
    $calls = (new \PhpParser\NodeFinder())->find($nodes, fn ($node): bool => $node instanceof \PhpParser\Node\Expr\MethodCall
        && $node->var instanceof \PhpParser\Node\Expr\FuncCall);
    $fact = [
        'start' => $calls[0]->getStartFilePos(), 'end' => $calls[0]->getEndFilePos(),
        'method' => 'execute', 'candidates' => [['App\Service::execute', 'App\Service::execute']], 'complete' => true,
    ];
    $reports = (new LaravelAuthenticationScanner(['App\Service::execute'], [], []))->scan(['routes.php' => $nodes], ['routes.php' => [$fact]]);

    expect($reports)->toMatchArray([[
        'file' => 'routes.php', 'line' => 5, 'operation' => 'App\Service::execute', 'operationLine' => 4, 'probability' => 80,
    ]]);
});
