<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe306\LaravelAuthenticationScanner;
use PhpParser\ParserFactory;

covers(LaravelAuthenticationScanner::class);

it('detects configured operations requested through the Laravel container', function (string $resolution): void {
    $source = 'namespace App; use App\AccountService as Service; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { \$service = $resolution; \$service->delete(); });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\AccountService::delete')
        ->and($reports[0]['probability'])->toBe(80);
})->with([
    'app(Service::class)',
    '\app(\App\AccountService::class)',
    'app(abstract: Service::class)',
    'app(Service::CLASS, parameters: [])',
    'app()->make(Service::class)',
    'app()->MAKE(abstract: Service::class, parameters: [])',
]);

it('does not resolve unsupported container syntax or unrelated factories', function (string $resolution): void {
    $source = 'namespace App; use App\AccountService as Service; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { \$service = $resolution; \$service->delete(); });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    'app()',
    'app("App\\\\AccountService")',
    'app($class)',
    'app($class::class)',
    'app(Service::UNKNOWN)',
    'app(self::class)',
    'app(...)',
    'app(...$arguments)',
    'app(other: Service::class)',
    'app()->make()',
    'app()->make(...)',
    'app()->make(...$arguments)',
    'app(Service::class, ...$parameters)',
    'app()->make(Service::class, ...$parameters)',
    'app(Service::{$constant})',
    'app()->{"make"}(Service::class)',
    'app()->build(Service::class)',
    'app("container")->make(Service::class)',
    '$container->make(Service::class)',
    'other(Service::class)',
]);

it('does not trust a shadowed app helper', function (string $namespace, string $resolution): void {
    $source = $namespace . ' use Illuminate\Support\Facades\Route; function app($abstract = null) {} '
        . "Route::post('/erase', function () { \$service = $resolution; \$service->delete(); });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with(['', 'namespace App;'])->with([
    'app(\App\AccountService::class)',
    'app()->make(\App\AccountService::class)',
]);

it('resolves imported container helpers without following requested bodies', function (string $resolution): void {
    $source = 'namespace App; use function app as resolveApp; use Illuminate\Support\Facades\Route; '
        . "function helper() { \$service = $resolution; \$service->delete(); } "
        . 'class AccountController { public function destroy() { helper(); } } '
        . 'Route::post("/erase", [AccountController::class, "destroy"]);';
    $reports = scanLaravelAuthentication($source, null);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\AccountService::delete')
        ->and($reports[0]['probability'])->toBe(40);
})->with([
    'resolveApp(AccountService::class)',
    'resolveApp()->make(AccountService::class)',
    '\APP(AccountService::class)',
]);

it('keeps container receiver facts separate from nested scopes and replacement values', function (string $body, int $count): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['$callback = function () { $service = app(AccountService::class); }; $service->delete();', 0],
    ['$callback = fn () => ($service = app(AccountService::class)); $service->delete();', 0],
    ['$service = app(AccountService::class); $copy = $service; $copy->delete();', 0],
    ['$service = app(AccountService::class); $service->{"delete"}();', 0],
    ['$service = new OtherService(); $service = app(AccountService::class); $service->delete();', 1],
    ['$service = app(OtherService::class); $service = new AccountService(); $service->delete();', 1],
    ['$service = app(AccountService::class); if (true) { $service = null; } $service->delete();', 0],
    ['$service = app(AccountService::class); $callback = function () use ($service) { $service = null; }; $service->delete();', 1],
]);

it('does not use a container request as proof of identity', function (string $resolution): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { \$request = $resolution; if (\$request->user()) { eraseAccounts(); } });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'app(\Illuminate\Http\Request::class)',
    'app()->make(\Illuminate\Http\Request::class)',
]);

it('does not enforce a requested container class authentication body', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class Guard {
    public function enforce() { if (!\Illuminate\Support\Facades\Auth::check()) { exit; } }
}
Route::post('/erase', function () {
    $guard = app(Guard::class);
    $guard->enforce();
    \eraseAccounts();
});
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('preserves container call ordering and reassignment limits', function (string $body, array $operations): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(array_column(scanLaravelAuthentication($source), 'operation'))->toBe($operations);
})->with([
    ['$service = app(AccountService::class, [\eraseAccounts()]); $service->delete();', ['eraseAccounts', 'App\AccountService::delete']],
    ['$service = app()->make(AccountService::class, [exit]); $service->delete();', []],
    ['$service = app(AccountService::class); $service = null; $service->delete();', []],
    ['if (true) { $service = app(AccountService::class); } $service->delete();', []],
    ['if (true) { $service = app(AccountService::class); $service->delete(); }', ['App\AccountService::delete']],
    ['$service = app(AccountService::class); $service->delete(); $service->delete();', ['App\AccountService::delete']],
]);

it('resolves locally constructed services', function (string $body, int $count): void {
    $source = 'namespace App; use App\AccountService as Service; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount($count);
    if ($count !== 0) {
        expect($reports[0]['operation'])->toBe('App\AccountService::delete')
            ->and($reports[0]['probability'])->toBe(80);
    }
})->with([
    [' $service = new Service(); $service->delete();', 1],
    [' $service = new \App\AccountService(); $service->delete();', 1],
    [' $service = new Service(); $service->other();', 0],
    [' $service = new Service(); $service = null; $service->delete();', 0],
    [' $service = new OtherService(); $service = new Service(); $service->delete();', 1],
    [' $service = new Service(); if (true) { $service->delete(); }', 1],
    [' if (true) { $service = new Service(); $service->delete(); }', 1],
    [' if (true) { $service = new Service(); } $service->delete();', 0],
    [' $service = new Service(); if (true) { $service = null; } $service->delete();', 0],
    [' $service = new Service(); $callback = function () use ($service) { $service = null; }; $service->delete();', 1],
    [' $service = new Service(); $callback = fn () => ($service = null); $service->delete();', 1],
    [' $service = new Service(); class Other { public function run() { $service = null; } } $service->delete();', 1],
    [' $service = new Service(); function unrelated() { $service = null; } $service->delete();', 1],
    [' $service = new Service(exit); $service->delete();', 0],
]);

it('does not trust request types changed by conditional or unsupported writes', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { $body if (\$request->user()) { eraseAccounts(); } });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'if (true) { $request = new \OtherRequest(); }',
    'while (true) { $request = new \OtherRequest(); break; }',
    '$value = ($request = new \OtherRequest());',
    '$request =& $other;',
    'unset($request);',
    '[$request] = [];',
    'list(, $request) = [];',
    '$request += 1;',
    '++$request;',
    '$request++;',
    '--$request;',
    '$request--;',
    '$$name = null;',
    'foreach ([] as $request) {}',
    'foreach ([] as $request => $value) {}',
]);

it('keeps object assignments separate from deferred and nested scopes', function (string $body): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    '$callback = function () { $service = new AccountService(); }; $service->delete();',
    '$callback = fn () => ($service = new AccountService()); $service->delete();',
    'function helper() { $service = new AccountService(); } $service->delete();',
    '$service = new $class(); $service->delete();',
    '$service = new class {}; $service->delete();',
    '$service = new AccountService(); $copy = $service; $copy->delete();',
]);

it('invalidates nested writes before an identity predicate', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'if (($request = other()) && $request->user()) { eraseAccounts(); }',
    'if (($request = other()) ? ($request->user() && eraseAccounts()) : null) {}',
    '$value = (($request = other()) ? ($request->user() && eraseAccounts()) : null);',
    '($request = other()) ? ($request->user() && eraseAccounts()) : null;',
    '$value = (($request = other()) && $request->user() && eraseAccounts());',
    '(($request = other()) && $request->user() && eraseAccounts());',
]);

it('follows locally constructed objects in controllers and helpers', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
function helper() { $service = new AccountService(); $service->delete(); }
class AccountController {
    public function destroy() { helper(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('checks constructor arguments before tracking the constructed object', function (): void {
    $reports = scanLaravelAuthentication('namespace App; use Illuminate\Support\Facades\Route; Route::post("/erase", function () { $service = new AccountService(\eraseAccounts()); $service->delete(); });');
    expect(array_column($reports, 'operation'))->toBe(['eraseAccounts', 'App\AccountService::delete']);
});

it('does not use a special class name as a local receiver type', function (string $class): void {
    $source = 'namespace App; use Illuminate\Support\Facades\Route; class AccountService { public function run() { $service = new '
        . $class . '(); $service->delete(); } } Route::post("/erase", [AccountService::class, "run"]);';
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with(['self', 'static', 'parent']);

function scanLaravelAuthentication(string $source, ?array $globalMiddleware = [], array $aliases = []): array
{
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse('<?php ' . $source);

    return (new LaravelAuthenticationScanner(
        ['App\AccountService::delete', 'eraseAccounts'],
        $aliases,
        $globalMiddleware,
    ))->scan(['routes.php' => $nodes]);
}

it('reports a configured critical function on a Laravel route', function (): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::post('/erase', function () { eraseAccounts(); });");

    expect($reports)->toHaveCount(1)
        ->and($reports[0])->toMatchArray(['file' => 'routes.php', 'line' => 1, 'operation' => 'eraseAccounts', 'probability' => 100]);
});

it('accepts effective authentication middleware', function (string $route): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; ' . $route))->toBe([]);
})->with([
    "Route::post('/erase', function () { eraseAccounts(); })->middleware('auth');",
    "Route::middleware(['web', 'auth:sanctum'])->group(function () { Route::post('/erase', function () { eraseAccounts(); }); });",
    "Route::middleware('auth')->group(function () { Route::post('/erase', function () { eraseAccounts(); })->withoutMiddleware('web'); });",
]);

it('reports routes after authentication middleware is removed', function (): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::middleware('auth')->group(function () { Route::post('/erase', function () { eraseAccounts(); })->withoutMiddleware('auth'); });");

    expect($reports)->toHaveCount(1);
});

it('accepts global authentication and configured aliases', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', function () { eraseAccounts(); })->middleware('members');";

    expect(scanLaravelAuthentication($source, ['auth']))->toBe([])
        ->and(scanLaravelAuthentication($source, [], ['members' => 'Illuminate\Auth\Middleware\Authenticate']))->toBe([]);
});

it('does not trust unknown middleware or missing global configuration', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', function () { eraseAccounts(); })->middleware('custom');";

    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60)
        ->and(scanLaravelAuthentication(str_replace("->middleware('custom')", '', $source), null)[0]['probability'])->toBe(60);
});

it('requires an enforced authentication branch before the operation', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body });";

    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['if (!Auth::check()) { return; } eraseAccounts();', 0],
    ['if (Auth::check()) { eraseAccounts(); }', 0],
    ['if (Auth::guest()) { throw new \RuntimeException(); } eraseAccounts();', 0],
    ['Auth::check(); eraseAccounts();', 1],
    ['eraseAccounts(); if (!Auth::check()) { return; }', 1],
    ["if (!Auth::check()) { redirect('/login'); } eraseAccounts();", 1],
    ['if (rand()) { if (!Auth::check()) { return; } } eraseAccounts();', 1],
    ['if (!Auth::check()) { exit; } eraseAccounts();', 0],
]);

it('follows controller and typed service calls per route', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountService { public function delete(): void {} }
class AccountController {
    public function destroy(AccountService $service): void { $service->delete(); }
}
Route::post('/public', [AccountController::class, 'destroy']);
Route::post('/private', [AccountController::class, 'destroy'])->middleware('auth');
PHP;
    $reports = scanLaravelAuthentication($source);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\AccountService::delete');
});

it('checks form request authorization and early validation hooks', function (string $requestBody, int $count): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    REQUEST_BODY
}
class AccountController {
    public function destroy(DeleteRequest $request): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication(str_replace('REQUEST_BODY', $requestBody, $source)))->toHaveCount($count);
})->with([
    ['public function authorize(): bool { return true; }', 1],
    ['public function authorize(): bool { return $this->user() !== null; }', 0],
    ['public function authorize(): bool { return false; }', 0],
    ['public function rules(): array { return []; }', 1],
    ['public function authorize(): bool { return $this->user() !== null; } protected function prepareForValidation(): void { \eraseAccounts(); }', 1],
]);

it('does not classify unrelated route classes or unlisted operations', function (): void {
    expect(scanLaravelAuthentication("class Route { static function post(\$uri, \$action) {} } Route::post('/erase', function () { eraseAccounts(); });"))->toBe([])
        ->and(scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::post('/erase', function () { saveContactForm(); });"))->toBe([]);
});

it('does not invent authentication from unresolved or recursive calls', function (): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; function recurse() { recurse(); eraseAccounts(); } Route::post('/erase', function () { unknownCheck(); recurse(); });");

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
});

it('validates critical operation names', function (): void {
    expect(fn () => new LaravelAuthenticationScanner([''], [], null))->toThrow(InvalidArgumentException::class);
});

it('checks controller middleware for the selected action', function (string $declaration, int $count): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function __construct() { DECLARATION }
    public function destroy(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication(str_replace('DECLARATION', $declaration, $source)))->toHaveCount($count);
})->with([
    ["\$this->middleware('auth');", 0],
    ["\$this->middleware('auth')->only('destroy');", 0],
    ["\$this->middleware('auth')->except('destroy');", 1],
    ["\$this->middleware('auth')->only('index');", 1],
]);

it('handles static group attributes and arrow route handlers', function (): void {
    expect(scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::group(['middleware' => 'auth'], function () { Route::post('/erase', fn () => eraseAccounts()); });"))->toBe([])
        ->and(scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts());"))->toHaveCount(1);
});

it('keeps state separate between scans', function (): void {
    $scanner = new LaravelAuthenticationScanner(['eraseAccounts']);
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse("<?php use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts());");

    expect($scanner->scan(['routes.php' => $nodes]))->toHaveCount(1)
        ->and($scanner->scan([]))->toBe([]);
});

it('follows authentication enforcement helpers without trusting ignored predicates', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "function requireUser() { $body } Route::post('/erase', function () { requireUser(); eraseAccounts(); });";

    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['if (!Auth::check()) { throw new \RuntimeException(); }', 0],
    ['if (!Auth::check()) { return; }', 1],
    ['return Auth::check();', 1],
    ['if (!Auth::check()) { exit; }', 0],
]);

it('checks operations in short circuit and conditional expressions', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body });";

    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['Auth::check() && eraseAccounts();', 0],
    ['Auth::guest() || eraseAccounts();', 0],
    ['Auth::check() ? eraseAccounts() : null;', 0],
    ['Auth::guest() ? eraseAccounts() : null;', 1],
    ['if (!Auth::check()) { return; } Auth::logout(); eraseAccounts();', 1],
]);

it('removes controller authentication middleware and honours exclusion order', function (string $route): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function __construct() { $this->middleware('auth'); }
    public function destroy(): void { \eraseAccounts(); }
}
ROUTE
PHP;
    expect(scanLaravelAuthentication(str_replace('ROUTE', $route, $source)))->toHaveCount(1);
})->with([
    "Route::post('/erase', [AccountController::class, 'destroy'])->withoutMiddleware('auth');",
    "Route::post('/erase', [AccountController::class, 'destroy'])->withoutMiddleware('auth')->middleware('auth');",
]);

it('keeps unsupported route declarations unknown', function (string $route, int $count, ?int $probability): void {
    $reports = scanLaravelAuthentication('use Illuminate\Support\Facades\Route; ' . $route);
    expect($reports)->toHaveCount($count);
    if ($probability !== null) {
        expect($reports[0]['probability'])->toBe($probability);
    }
})->with([
    ["Route::post(...);", 0, null],
    ["Route::post('/erase', fn () => eraseAccounts())->middleware(...);", 0, null],
    ["Route::post('/erase', fn () => eraseAccounts())->{\$method}();", 1, 60],
    ["Route::post('/erase', fn () => eraseAccounts())->middleware(\$middleware);", 1, 60],
    ["Route::post('/erase', fn () => eraseAccounts())->middleware(['key' => 'auth']);", 1, 60],
    ["Route::post('/erase', fn () => eraseAccounts())->middleware([\$middleware]);", 1, 60],
    ["Route::post('/erase', fn () => eraseAccounts())->withoutMiddleware(\$middleware);", 1, 60],
    ["Route::post('/erase', fn () => eraseAccounts())->custom();", 1, 60],
    ["Route::group(['middleware' => 'auth', 'prefix' => '/accounts'], function () { Route::post('/erase', fn () => eraseAccounts()); });", 0, null],
    ["Route::group(['controller' => 'Unknown'], function () { Route::post('/erase', fn () => eraseAccounts()); });", 1, 60],
    ["Route::post(action: fn () => eraseAccounts(), uri: '/erase');", 1, 100],
    ["Route::post('/erase', []);", 0, null],
    ["Route::post('/erase', 'MissingController');", 0, null],
]);

it('does not trust unsupported controller middleware declarations', function (string $declaration): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    DECLARATION
    public function destroy(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication(str_replace('DECLARATION', $declaration, $source))[0]['probability'])->toBe(60);
})->with([
    'public static function middleware(): array { return ["auth"]; }',
    'public function __construct() { if (true) { $this->middleware("auth"); } }',
    'public function __construct() { $this->middleware("auth")->only($actions); }',
    'public function __construct() { $this->middleware($middleware); }',
    'public function __construct() { configureAuthentication(); }',
]);

it('resolves inherited controllers and form requests', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class BaseRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return null !== $this->user(); }
}
class DeleteRequest extends BaseRequest {}
class BaseController extends \Illuminate\Routing\Controller {
    public function destroy(DeleteRequest $request): void { \eraseAccounts(); }
}
class AccountController extends BaseController {}
Route::post('/erase', 'App\AccountController@destroy');
Route::post('/closure', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('does not accept custom authorization lifecycle or identity methods', function (string $extra, string $authorization): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    EXTRA
    public function authorize(): bool { AUTHORIZATION }
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    $reports = scanLaravelAuthentication(str_replace(['EXTRA', 'AUTHORIZATION'], [$extra, $authorization], $source));
    expect($reports)->toHaveCount(1);
})->with([
    ['public function failedAuthorization(): void {}', 'return false;'],
    ['public function passesAuthorization(): bool { return true; }', 'return false;'],
    ['public function validateResolved(): void {}', 'return false;'],
    ['public function user() { return new \stdClass(); }', 'return $this->user() !== null;'],
    ['', 'if ($this->user()) { return true; } return false;'],
]);

it('checks critical controller actions after form request authorization', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse(<<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return $this->user() !== null; }
}
class AccountController {
    public function destroy(DeleteRequest $request): void {}
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP);
    expect((new LaravelAuthenticationScanner(['App\AccountController::destroy']))->scan(['routes.php' => $nodes]))->toBe([]);
});

it('does not follow work after a stopping form request hook', function (string $requestBody): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest { REQUEST_BODY }
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication(str_replace('REQUEST_BODY', $requestBody, $source)))->toBe([]);
})->with([
    'protected function prepareForValidation(): void { exit; }',
    'public function authorize(): bool { throw new \RuntimeException(); }',
]);

it('keeps complex call paths at a lower confidence', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
})->with([
    'if (rand()) { echo "first"; } elseif (rand()) { eraseAccounts(); }',
    '$callback = function () {}; eraseAccounts();',
    '$callback = eraseAccounts(...); eraseAccounts();',
    '$value = rand() ?? 1; eraseAccounts();',
    'while (rand()) { eraseAccounts(); }',
    'match (rand()) { 0 => eraseAccounts(), default => null };',
    'require "unknown.php"; eraseAccounts();',
    '$receiver?->unknown(); eraseAccounts();',
]);

it('resolves namespaced helpers and self calls', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
function helper() { \eraseAccounts(); }
class AccountController {
    public function __invoke(): void { self::erase(); }
    public static function erase(): void { helper(); }
}
Route::post('/erase', AccountController::class);
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('does not confuse a shadowed function with a critical global function', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
function eraseAccounts(): void {}
Route::post('/erase', function () { eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('recognizes request and authentication helper guards', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['if (auth()->check()) { eraseAccounts(); }', 0],
    ['if (auth()->guest()) { return; } eraseAccounts();', 0],
    ['if ($request->user() === null) { return; } eraseAccounts();', 0],
    ['$request = null; eraseAccounts();', 1],
    ['auth()->unknown(); eraseAccounts();', 1],
    ['auth()->check(1); eraseAccounts();', 1],
]);

it('does not accept an identity check when the receiver type is unknown', function (string $parameter, string $assignment): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function ($parameter) { $assignment if (\$request->user() !== null) { eraseAccounts(); } });";
    $reports = scanLaravelAuthentication($source);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('eraseAccounts')
        ->and($reports[0]['probability'])->toBe(80);
})->with([
    'untyped parameter' => ['$request', ''],
    'mixed parameter' => ['mixed $request', ''],
    'replaced request object' => ['\Illuminate\Http\Request $request', '$request = unknownRequest();'],
]);

it('does not miss critical calls in receivers or arguments', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'eraseAccounts()->unknown();',
    'eraseAccounts()->unknown(...);',
    'auth(eraseAccounts())->check();',
    '$value = [eraseAccounts()];',
    'eraseAccounts(); eraseAccounts();',
]);

it('does not scan calls after unconditional termination', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', function () { exit; eraseAccounts(); });";
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('does not scan arguments after a terminating argument', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', function () { unknownCall(exit, eraseAccounts()); });";
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('handles configured critical route actions without a local body', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $scanner = new LaravelAuthenticationScanner(['App\AccountController::destroy']);
    $source = "<?php use Illuminate\Support\Facades\Route; Route::post('/erase', [App\AccountController::class, 'destroy']);";
    expect($scanner->scan(['routes.php' => $parser->parse($source)]))->toHaveCount(1);
});

it('reports configured critical controller actions without authentication', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $scanner = new LaravelAuthenticationScanner(['App\AccountController::destroy']);
    $source = "<?php namespace App; use Illuminate\Support\Facades\Route; class AccountController { public function destroy(): void {} } Route::post('/erase', [AccountController::class, 'destroy']);";
    expect($scanner->scan(['routes.php' => $parser->parse($source)]))->toHaveCount(1);
});

it('stops recursive request inheritance', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class FirstRequest extends SecondRequest {}
class SecondRequest extends FirstRequest {}
Route::post('/erase', function (FirstRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('distinguishes coalescing from Boolean conditions', function (): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { Auth::check() ?? eraseAccounts(); });";
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('resolves cross-file service bodies', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $files = [
        'routes.php' => $parser->parse("<?php use Illuminate\Support\Facades\Route; Route::post('/erase', [App\AccountController::class, 'destroy']);"),
        'controller.php' => $parser->parse('<?php namespace App; class AccountController { public function destroy(): void { \eraseAccounts(); } }'),
    ];
    expect((new LaravelAuthenticationScanner(['eraseAccounts']))->scan($files))->toHaveCount(1);
});

it('invalidates authentication after a logout helper', function (): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
function signOut(): void { auth()->logout(); }
Route::post('/erase', function () {
    if (!Auth::check()) { return; }
    signOut();
    eraseAccounts();
});
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('matches a configured inherited critical method', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse(<<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
class AccountService { public function delete(): void {} }
class ChildAccountService extends AccountService {}
Route::post('/erase', function (ChildAccountService $service) { $service->delete(); });
PHP);
    expect((new LaravelAuthenticationScanner(['App\AccountService::delete']))->scan(['routes.php' => $nodes]))->toHaveCount(1);
});

it('normalizes critical operation names without changing the report name', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
use Illuminate\Support\Facades\Route;
Route::post('/erase', function () { ERASEACCOUNTS(); });
PHP);
    $reports = (new LaravelAuthenticationScanner(['\eraseAccounts']))->scan(['routes.php' => $nodes]);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('eraseAccounts');
});

it('checks each supported HTTP route method', function (string $method): void {
    $arguments = $method === 'match' ? "['DELETE'], '/erase'," : "'/erase',";
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::$method($arguments function () { eraseAccounts(); });");

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
})->with(['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match']);

it('does not lower confidence for route attributes that do not change authentication', function (string $attribute): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->$attribute;");

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
})->with([
    "name('erase')",
    "prefix('accounts')",
    "domain('example.test')",
    "where('id', '[0-9]+')",
    "whereNumber('id')",
    "whereSlug('slug')",
]);

it('keeps unknown group attributes unknown even with a known middleware item', function (string $attributes): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::group($attributes, function () { Route::post('/erase', fn () => eraseAccounts()); });");

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(60);
})->with([
    "['controller' => 'Unknown', 'middleware' => []]",
    "['middleware' => [], 'controller' => 'Unknown']",
    "['middleware' => \$unknown]",
    "['middleware' => [], 0 => 'unknown']",
]);

it('accepts supported group attributes without changing confidence', function (string $attribute): void {
    $reports = scanLaravelAuthentication("use Illuminate\Support\Facades\Route; Route::group([$attribute], function () { Route::post('/erase', fn () => eraseAccounts()); });");

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
})->with(["'prefix' => '/accounts'", "'as' => 'accounts.'", "'domain' => 'example.test'", "'where' => []"]);

it('retains the rest of a route chain after an unknown method name', function (): void {
    $source = 'use Illuminate\Support\Facades\Route; Route::post("/erase", fn () => eraseAccounts())->{$method}()->middleware("auth");';
    $reports = scanLaravelAuthentication($source);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(60);
});

it('does not confuse other static calls or dynamic route names with routes', function (string $source): void {
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    'use Illuminate\Support\Facades\Route; $class::post("/erase", fn () => eraseAccounts());',
    'use Illuminate\Support\Facades\Route; Route::{$method}("/erase", fn () => eraseAccounts());',
    'OtherRoute::post("/erase", fn () => eraseAccounts());',
    '$route->post("/erase", fn () => eraseAccounts());',
]);

it('keeps inherited authentication when a nested route adds no middleware', function (): void {
    $source = 'use Illuminate\Support\Facades\Route; Route::middleware("auth")->group(function () { Route::post("/erase", fn () => eraseAccounts())->middleware([]); });';
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('keeps checking operations after a duplicate operation on the same route', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
Route::post('/erase', function (AccountService $service) {
    \eraseAccounts();
    \eraseAccounts();
    $service->delete();
});
PHP;
    $reports = scanLaravelAuthentication($source);

    expect(array_column($reports, 'operation'))->toBe(['eraseAccounts', 'App\AccountService::delete']);
});

it('resolves a string controller action and its exact source positions', function (): void {
    $reports = scanLaravelAuthentication(<<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function destroy(): void {
        \eraseAccounts();
    }
}
Route::delete('/erase', 'App\AccountController@destroy');
PHP);

    expect($reports)->toBe([[
        'file' => 'routes.php',
        'line' => 8,
        'operation' => 'eraseAccounts',
        'operationLine' => 5,
        'probability' => 100,
    ]]);
});

it('resolves full middleware class names and aliases with guard parameters', function (string $middleware): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->middleware($middleware);";
    expect(scanLaravelAuthentication($source, [], ['members' => 'Illuminate\Auth\Middleware\Authenticate']))->toBe([]);
})->with([
    '\Illuminate\Auth\Middleware\Authenticate::class',
    '\Illuminate\Auth\Middleware\Authenticate::CLASS',
    "'members:sanctum'",
]);

it('does not trust middleware constants or dynamic class names', function (string $middleware): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->middleware($middleware);";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60);
})->with([
    '\Illuminate\Auth\Middleware\Authenticate::UNKNOWN',
    '$class::class',
    '\Illuminate\Auth\Middleware\Authenticate::{$constant}',
]);

it('recognizes the global Laravel route alias', function (): void {
    expect(scanLaravelAuthentication("Route::delete('/erase', fn () => eraseAccounts());")[0]['probability'])->toBe(100);
});

it('does not replace a configured auth alias with the built-in middleware', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->middleware('auth');";
    expect(scanLaravelAuthentication($source, [], ['auth' => 'App\CustomMiddleware'])[0]['probability'])->toBe(60);
});

it('keeps middleware removals when there is more than one exclusion', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->middleware('auth')->withoutMiddleware('auth')->withoutMiddleware('web');";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(100);
});

it('does not accept an unrelated named argument as positional middleware', function (): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', fn () => eraseAccounts())->middleware(other: 'auth');";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60);
});

it('checks controller middleware with the exact action and parent configuration', function (string $parent, string $declaration, int $count, ?int $probability): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController extends PARENT_CLASS {
    public function __construct() { DECLARATION }
    public function destroy(): void { \eraseAccounts(); }
}
Route::delete('/erase', [AccountController::class, 'destroy']);
PHP;
    $reports = scanLaravelAuthentication(str_replace(['PARENT_CLASS', 'DECLARATION'], [$parent, $declaration], $source));

    expect($reports)->toHaveCount($count);
    if ($probability !== null) {
        expect($reports[0]['probability'])->toBe($probability);
    }
})->with([
    ['\Illuminate\Routing\Controller', '', 1, 100],
    ['UnknownController', '', 1, 60],
    ['\Illuminate\Routing\Controller', '$this->middleware("auth")->except("index");', 0, null],
    ['\Illuminate\Routing\Controller', '$this->MIDDLEWARE("auth")->ONLY("destroy");', 0, null],
    ['\Illuminate\Routing\Controller', '$this->middleware("auth")->EXCEPT("index");', 0, null],
    ['\Illuminate\Routing\Controller', '$other->middleware("auth");', 1, 60],
    ['\Illuminate\Routing\Controller', '$this->unknown("auth");', 1, 60],
    ['\Illuminate\Routing\Controller', '$this->{"middleware"}("auth");', 1, 60],
    ['\Illuminate\Routing\Controller', 'self::middleware("auth");', 1, 60],
    ['\Illuminate\Routing\Controller', '$this->receiver->middleware("auth");', 1, 60],
    ['\Illuminate\Routing\Controller', '$this->{"only"}("destroy");', 1, 60],
    ['\Illuminate\Routing\Controller', 'OtherClass::only("destroy");', 1, 60],
]);

it('stops cyclic controller inheritance without assuming missing authentication', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class FirstController extends SecondController {
    public function destroy(): void { \eraseAccounts(); }
}
class SecondController extends FirstController {}
Route::post('/erase', [FirstController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60);
});

it('keeps inherited authentication for a controller action', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class BaseController {
    public function __construct() { $this->middleware('auth')->only('destroy'); }
}
class AccountController extends BaseController {
    public function destroy(): void { \eraseAccounts(); }
}
Route::delete('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('lowers confidence only when a call chain reaches the depth limit', function (int $depth, int $probability): void {
    $functions = [];
    for ($index = 0; $index < $depth; $index++) {
        $body = $index + 1 < $depth ? 'step' . ($index + 1) . '();' : '';
        $functions[] = "function step$index(): void { $body }";
    }
    $source = 'use Illuminate\Support\Facades\Route; '
        . implode("\n", $functions)
        . " Route::post('/erase', function () { step0(); eraseAccounts(); });";

    $reports = scanLaravelAuthentication($source);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('eraseAccounts')
        ->and($reports[0]['probability'])->toBe($probability);
})->with([
    'below the limit' => [15, 100],
    'last supported call' => [16, 100],
    'first unsupported call' => [17, 80],
    'beyond the limit' => [18, 80],
]);

it('does not treat an expression before an authentication check as a function return', function (string $termination): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
function requireUser(): void {
    $message = 'Authentication required';
    if (!Auth::check()) { TERMINATION }
}
Route::post('/erase', function () { requireUser(); eraseAccounts(); });
PHP;

    expect(scanLaravelAuthentication(str_replace('TERMINATION', $termination, $source)))->toBe([]);
})->with([
    'throw new \RuntimeException();',
    'exit;',
    'return throw new \RuntimeException();',
    'return exit;',
]);

it('checks all injected requests rather than stopping at an unrelated parameter', function (string $firstParameter): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return $this->user() !== null; }
}
Route::post('/erase', function (FIRST_PARAMETER, DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication(str_replace('FIRST_PARAMETER', $firstParameter, $source)))->toBe([]);
})->with([
    'string $id',
    'OtherService $service',
    '\Illuminate\Foundation\Http\FormRequest $plainRequest',
]);

it('continues request analysis after an unknown authorization lifecycle', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class UnknownRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return true; }
    public function failedAuthorization(): void {}
}
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return $this->user() !== null; }
}
Route::post('/erase', function (UnknownRequest $unknown, DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('preserves authentication established by a request preparation hook', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    protected function prepareForValidation(): void {
        if (!Auth::check()) { throw new \RuntimeException(); }
    }
    public function authorize(): bool { return true; }
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('does not claim full confidence for unsupported request authorization', function (string $authorization): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize() { AUTHORIZATION }
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    $reports = scanLaravelAuthentication(str_replace('AUTHORIZATION', $authorization, $source));
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
})->with([
    '$allowed = true; return $allowed;',
    'if (true) { return true; }',
    '$allowed = true;',
]);

it('accepts a constant denial with any PHP keyword case', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return FALSE; }
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('follows instance calls through the current controller receiver', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function destroy(): void { $this->remove(); }
    public function remove(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100)
        ->and($reports[0]['operationLine'])->toBe(5);
});

it('keeps self and the runtime receiver separate for inherited methods', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class BaseController {
    public function destroy(): void { $this->remove(); }
    public function remove(): void {}
}
class AccountController extends BaseController {
    public function remove(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('does not apply form request resolution to an ordinary service call', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return false; }
}
function remove(DeleteRequest $request): void { \eraseAccounts(); }
Route::post('/erase', function () { remove(new DeleteRequest()); });
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('resolves mixed-case inherited method calls', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class BaseController { public function destroy(): void { \eraseAccounts(); } }
class AccountController extends BaseController {}
Route::post('/erase', [AccountController::class, 'DESTROY']);
PHP;
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
});

it('does not accept an identity check on an unsupported parameter type', function (string $type): void {
    $source = "use Illuminate\Support\Facades\Route; Route::post('/erase', function ($type \$request) { if (\$request->user()) { eraseAccounts(); } });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
})->with(['?\Illuminate\Http\Request', '\OtherRequest', 'object', '\Illuminate\Http\Request|\OtherRequest']);

it('recognizes case-insensitive authentication methods', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { $body });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    'if ($request->user()) { eraseAccounts(); }',
    'if ($request->USER() !== null) { eraseAccounts(); }',
    'if (null === $request->user()) { return; } eraseAccounts();',
    'if (auth()->CHECK()) { eraseAccounts(); }',
    'if (auth()->GUEST()) { return; } eraseAccounts();',
    'if (Auth::CHECK()) { eraseAccounts(); }',
    'if (Auth::GUEST()) { return; } eraseAccounts();',
]);

it('does not trust dynamic identity and authentication method names', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { $body });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
})->with([
    'if ($request->{"user"}()) { eraseAccounts(); }',
    'if (auth()->{"check"}()) { eraseAccounts(); }',
    'if (Auth::{"check"}()) { eraseAccounts(); }',
    'if ($authentication::check()) { eraseAccounts(); }',
    'if ($request->nested->user()) { eraseAccounts(); }',
    'if ($requests[0]->user()) { eraseAccounts(); }',
    'if ($authentication->check()) { eraseAccounts(); }',
    '$helper = "auth"; if ($helper()->check()) { eraseAccounts(); }',
]);

it('preserves guest paths from both sides of conditional expressions', function (string $expression): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $expression eraseAccounts(); });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'Auth::check() ? null : null;',
    'Auth::guest() ? null : null;',
    'Auth::check() && true;',
    'Auth::guest() && true;',
    'Auth::check() || false;',
    'Auth::guest() || false;',
]);

it('does not lose an else branch or treat it as unconditional', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['if (Auth::guest()) { return; } else { eraseAccounts(); }', 0],
    ['if (Auth::check()) { return; } else { eraseAccounts(); }', 1],
    ['if (Auth::check()) {} else { return; } eraseAccounts();', 0],
    ['if (Auth::guest()) {} else { return; } eraseAccounts();', 1],
]);

it('does not classify a replacement object as a request', function (): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Route;
class OtherRequest { public function user(): object { return new \stdClass(); } }
Route::post('/erase', function (\Illuminate\Http\Request $request) {
    $request = new OtherRequest();
    if ($request->user() !== null) { eraseAccounts(); }
});
PHP;
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
});

it('invalidates an established identity after mixed-case logout calls', function (string $logout, int $probability): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { if (!Auth::check()) { return; } $logout eraseAccounts(); });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe($probability);
})->with([
    ['Auth::LOGOUT();', 100],
    ['auth()->LOGOUT();', 80],
]);

it('does not trust a replacement authentication helper', function (string $namespace): void {
    $source = <<<'PHP'
NAMESPACE
use Illuminate\Support\Facades\Route;
class GuestService { public function check(): bool { return true; } }
function auth(): GuestService { return new GuestService(); }
Route::post('/erase', function () { if (auth()->check()) { \eraseAccounts(); } });
PHP;
    expect(scanLaravelAuthentication(str_replace('NAMESPACE', $namespace, $source)))->toHaveCount(1);
})->with(['', 'namespace App;']);

it('resolves namespaced helpers without regard to function name case', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
function helper(): void { \eraseAccounts(); }
Route::post('/erase', function () { HELPER(); });
PHP;
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
});

it('resolves self and static calls to the correct inherited class', function (string $receiver, int $count): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class BaseController {
    public function destroy(): void { RECEIVER::remove(); }
    public static function remove(): void {}
}
class AccountController extends BaseController {
    public static function remove(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication(str_replace('RECEIVER', $receiver, $source)))->toHaveCount($count);
})->with([
    ['self', 0],
    ['SELF', 0],
    ['static', 1],
    ['STATIC', 1],
]);

it('finds a critical operation in a later match arm', function (): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
Route::post('/erase', function () {
    match (true) {
        Auth::check() => throw new \RuntimeException(),
        default => eraseAccounts(),
    };
});
PHP;
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80)
        ->and($reports[0]['operationLine'])->toBe(6);
});

it('keeps a normal match arm reachable after another arm stops', function (): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Route;
Route::post('/erase', function () {
    match (true) { true => throw new \RuntimeException(), default => null };
    eraseAccounts();
});
PHP;
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80)
        ->and($reports[0]['operationLine'])->toBe(4);
});

it('inspects critical operations before throw and exit stop execution', function (string $termination): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $termination eraseAccounts(); });";
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(100);
})->with(['throw eraseAccounts();', 'exit(eraseAccounts());']);

it('checks critical arguments before an authentication helper call', function (string $expression): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $expression });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'if (auth(eraseAccounts())->check()) {}',
    'if (auth()->check(eraseAccounts())) {}',
]);

it('keeps scanning a route chain after an unknown method name', function (): void {
    $reports = scanLaravelAuthentication(<<<'PHP'
use Illuminate\Support\Facades\Route;
Route::prefix('/accounts')->{$method}()->post('/erase', fn () => eraseAccounts());
PHP);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(60);
});

it('rejects expression names for static route methods', function (): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; Route::{"post"}("/erase", fn () => eraseAccounts());'))->toBe([]);
});

it('preserves inherited middleware in static group attributes', function (): void {
    expect(scanLaravelAuthentication(<<<'PHP'
use Illuminate\Support\Facades\Route;
Route::middleware('auth')->group(function () {
    Route::group(['middleware' => []], function () {
        Route::post('/erase', fn () => eraseAccounts());
    });
});
PHP))->toBe([]);
});

it('does not trust group attributes without literal string keys', function (string $key): void {
    $source = 'use Illuminate\Support\Facades\Route; Route::group([' . $key
        . ' => "auth"], function () { Route::post("/erase", fn () => eraseAccounts()); });';
    $reports = scanLaravelAuthentication($source);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(60);
})->with(['0', '$key', 'null']);

it('does not trust constructor middleware on a property named this', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function __construct() { $container->this->middleware('auth'); }
    public function destroy(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60);
});

it('does not trust constructor middleware on an array element', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class AccountController {
    public function __construct() { $container[0]->middleware('auth'); }
    public function destroy(): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(60);
});

it('does not invent authentication for cyclic request inheritance', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class FirstRequest extends SecondRequest {
    public function authorize(): bool { return false; }
}
class SecondRequest extends FirstRequest {}
Route::post('/erase', function (FirstRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(100);
});

it('keeps custom request lifecycle findings at a lower confidence', function (string $method): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function authorize(): bool { return false; }
    public function METHOD() {}
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication(str_replace('METHOD', $method, $source))[0]['probability'])->toBe(80);
})->with(['failedAuthorization', 'passesAuthorization', 'validateResolved']);

it('stops request resolution before a later request can run', function (string $hook): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class StoppedRequest extends \Illuminate\Foundation\Http\FormRequest { HOOK }
class LaterRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function prepareForValidation(): void { \eraseAccounts(); }
}
Route::post('/erase', function (StoppedRequest $first, LaterRequest $second) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication(str_replace('HOOK', $hook, $source)))->toBe([]);
})->with([
    'public function prepareForValidation(): void { exit; }',
    'public function authorize(): bool { throw new \RuntimeException(); }',
]);

it('continues after a request preparation hook that returns normally', function (): void {
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function prepareForValidation(): void {}
    public function authorize(): bool { return true; }
}
Route::post('/erase', function (DeleteRequest $request) { \eraseAccounts(); });
PHP;
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(100);
});

it('does not let unsupported statements restore full confidence', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body eraseAccounts(); });";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(80);
})->with([
    'if (Auth::check()) {} elseif (Auth::guest()) {}',
    'while (true) { break; }',
    'match (true) { true => null, default => null };',
    '$callback = fn () => null;',
]);

it('keeps work inside deferred callbacks separate from the route', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    '$callback = function () { eraseAccounts(); };',
    '$callback = fn () => eraseAccounts();',
]);

it('checks critical match conditions before the arm bodies', function (): void {
    $reports = scanLaravelAuthentication('use Illuminate\Support\Facades\Route; Route::post("/erase", function () { match (eraseAccounts()) { default => null }; });');
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['probability'])->toBe(80);
});

it('checks both supported short-circuit branches', function (string $expression, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $expression; });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['Auth::check() and eraseAccounts()', 0],
    ['Auth::guest() and eraseAccounts()', 1],
    ['Auth::check() or eraseAccounts()', 1],
    ['Auth::guest() or eraseAccounts()', 0],
    ['Auth::check() && eraseAccounts()', 0],
    ['Auth::guest() && eraseAccounts()', 1],
    ['Auth::check() || eraseAccounts()', 1],
    ['Auth::guest() || eraseAccounts()', 0],
    ['Auth::check() ? null : eraseAccounts()', 1],
    ['Auth::guest() ? null : eraseAccounts()', 0],
]);

it('does not apply authentication facts from unsupported statement branches', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body eraseAccounts(); });";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(80);
})->with([
    'while (true) { if (!Auth::check()) { exit; } }',
    'do { if (!Auth::check()) { exit; } } while (false);',
    'for (; true;) { if (!Auth::check()) { exit; } }',
    'switch (true) { case true: exit; }',
]);

it('preserves expression evaluation order outside call arguments', function (string $expression): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $expression; });";
    expect(scanLaravelAuthentication($source))->toBe([]);
})->with([
    '(exit) + eraseAccounts()',
    '[(exit), eraseAccounts()]',
]);

it('does not accept method references or calls with arguments as authentication', function (string $check): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { if ($check) { eraseAccounts(); } });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'Auth::check(...)',
    'auth()->check(...)',
    'Auth::check(1)',
    'auth()->guest(1)',
]);

it('requires a null comparison rather than another identity value', function (string $check, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function (\\Illuminate\\Http\\Request \$request) { if ($check) { eraseAccounts(); } });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['NULL !== $request->user()', 0],
    ['$request->user() !== NULL', 0],
    ['true !== $request->user()', 1],
    ['$request->user() !== true', 1],
    ['$value !== $request->user()', 1],
    ['$request->user() !== $value', 1],
    ['"null" !== $request->user()', 1],
    ['$request->user() !== "null"', 1],
]);

it('keeps nullable method receivers and arguments on separate paths', function (string $body, int $count): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount($count);
})->with([
    ['$receiver?->run(exit); eraseAccounts();', 1],
    ['$receiver->run(exit); eraseAccounts();', 0],
    ['eraseAccounts()?->run();', 1],
    ['Auth::check(exit); eraseAccounts();', 0],
]);

it('does not let an unreachable expression reduce confidence', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . "Route::post('/erase', function () { eraseAccounts(); $body });";
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(100);
})->with([
    'unknownCall(exit, unknownCall());',
    'unknownCall(exit, function () {});',
    'exit; while (true) {}',
    'throw $exception;',
    '(exit) + unknownCall();',
]);

it('reports exact positions for critical controller entry points', function (bool $hasBody): void {
    $source = <<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
CONTROLLER
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    $controller = $hasBody ? 'class AccountController { public function destroy(): void { \eraseAccounts(); } }' : '';
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(str_replace('CONTROLLER', $controller, $source));
    $reports = (new LaravelAuthenticationScanner(['App\AccountController::destroy']))->scan(['routes.php' => $nodes]);
    expect($reports)->toBe([[
        'file' => 'routes.php', 'line' => 5, 'operation' => 'App\AccountController::destroy',
        'operationLine' => 5, 'probability' => $hasBody ? 60 : 40,
    ]]);
})->with([true, false]);

it('keeps a configured child action name when its body is inherited', function (): void {
    $source = <<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
class BaseController { public function destroy(): void {} }
class AccountController extends BaseController {}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse($source);
    $reports = (new LaravelAuthenticationScanner(['App\AccountController::destroy']))->scan(['routes.php' => $nodes]);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\AccountController::destroy');
});

it('resolves configured namespaced operations without a local function body', function (): void {
    $source = '<?php namespace App; use Illuminate\Support\Facades\Route; Route::post("/erase", fn () => ERASEACCOUNTS());';
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse($source);
    $reports = (new LaravelAuthenticationScanner(['App\eraseAccounts']))->scan(['routes.php' => $nodes]);
    expect($reports)->toHaveCount(1)
        ->and($reports[0]['operation'])->toBe('App\eraseAccounts');
});

it('keeps branch states unique and indexed as a list', function (string $body, array $states, array $expected): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $body);
    $scanner = new LaravelAuthenticationScanner();

    // At most two states are needed. Repeated states can multiply work at each branch.
    expect(invade($scanner)->flow($nodes, $states, [], [], [], true))->toBe($expected);
})->with([
    ['if (\Illuminate\Support\Facades\Auth::check()) {} else {}', [false, true], [true, false]],
    ['\Illuminate\Support\Facades\Auth::check() ? null : null;', [false, true], [true, false]],
    ['match (true) { 0 => null, 1 => null, default => \Illuminate\Support\Facades\Auth::logout() };', [true], [true, false]],
    ['$receiver?->run();', [false, true], [false, true]],
]);

it('retains the declaring class only for class methods', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php namespace App; function helper() {} class AccountController { public function destroy() {} }');
    $scanner = new LaravelAuthenticationScanner();
    $scanner->scan(['source.php' => $nodes]);

    expect(invade($scanner)->body('App\helper')['class'])->toBeNull()
        ->and(invade($scanner)->body('App\helper')['symbol'])->toBe('App\helper')
        ->and(invade($scanner)->body('App\AccountController::destroy')['class'])->toBe('App\AccountController')
        ->and(invade($scanner)->body('App\AccountController::destroy')['symbol'])->toBe('App\AccountController::destroy');
});

it('creates receiver types only when a receiver exists', function (): void {
    $scanner = new LaravelAuthenticationScanner();
    expect(invade($scanner)->types([]))->toBe([])
        ->and(invade($scanner)->types([], 'App\AccountController'))->toBe(['this' => 'App\AccountController']);
});

it('does not trust unsupported parameter nodes or dynamic variable names', function (): void {
    $scanner = new LaravelAuthenticationScanner();
    $type = new \PhpParser\Node\Name\FullyQualified('Illuminate\Http\Request');
    $parameters = [
        new \PhpParser\Node\Param(new \PhpParser\Node\Expr\Error(), type: $type),
        new \PhpParser\Node\Param(new \PhpParser\Node\Expr\Variable(new \PhpParser\Node\Expr\Variable('name')), type: $type),
    ];
    expect(invade($scanner)->types($parameters))->toBe([]);
});

it('does not accept a dynamic static base as a known route chain', function (): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; Route::{$method}()->post("/erase", fn () => eraseAccounts());'))->toBe([]);
});

it('leaves middleware unknown when its argument is missing', function (): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; Route::post("/erase", fn () => eraseAccounts())->middleware();')[0]['probability'])->toBe(60);
});

it('does not replace a request type when assigning an array element', function (): void {
    $source = <<<'PHP'
use Illuminate\Support\Facades\Route;
Route::post('/erase', function (\Illuminate\Http\Request $request) {
    $items[0] = null;
    if ($request->user()) { eraseAccounts(); }
});
PHP;
    expect(scanLaravelAuthentication($source))->toBe([]);
});

it('does not restore execution after a logout argument stops it', function (): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; Route::post("/erase", function () { Auth::logout(exit); eraseAccounts(); });'))->toBe([]);
});

it('keeps confidence low when nullable arguments can stop execution', function (): void {
    $source = 'use Illuminate\Support\Facades\Route; Route::post("/erase", function () { eraseAccounts(); $receiver?->run(exit); });';
    expect(scanLaravelAuthentication($source)[0]['probability'])->toBe(80);
});

it('keeps possible states from unsupported elseif branches', function (string $body, array $expected): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $body);
    expect(invade(new LaravelAuthenticationScanner())->flow($nodes, [false], [], [], [], true))->toBe($expected);
})->with([
    ['if (\Illuminate\Support\Facades\Auth::guest()) { return; } elseif (true) {} else {}', [true, false]],
    ['if (\Illuminate\Support\Facades\Auth::check()) { return; } elseif (true) {} else { return; }', [false]],
]);

it('keeps nullable call states unique after argument evaluation', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
function enforce() { if (!\Illuminate\Support\Facades\Auth::check()) { exit; } }
$receiver?->run(enforce());
PHP);
    $scanner = new LaravelAuthenticationScanner();
    $scanner->scan(['source.php' => $nodes]);
    expect(invade($scanner)->flow([$nodes[1]], [true, false], [], [], [], true))->toBe([true, false]);
});

it('retains a logout effect in the non-null branch of a nullable call', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php $receiver?->run(\Illuminate\Support\Facades\Auth::logout());');
    expect(invade(new LaravelAuthenticationScanner())->flow($nodes, [true], [], [], [], true))->toBe([false, true]);
});

it('keeps unsupported statement children on separate paths', function (string $body): void {
    $source = 'use Illuminate\Support\Facades\Route; '
        . "Route::post('/erase', function () { $body });";
    expect(scanLaravelAuthentication($source))->toHaveCount(1);
})->with([
    'while (exit) { eraseAccounts(); }',
    'for (exit; eraseAccounts();) {}',
]);

it('handles null items in a destructuring expression', function (): void {
    expect(scanLaravelAuthentication('use Illuminate\Support\Facades\Route; Route::post("/erase", function () { [, $value] = []; eraseAccounts(); });'))->toHaveCount(1);
});

it('counts the controller entry when limiting request hook calls', function (int $depth, int $probability): void {
    $functions = [];
    for ($index = 0; $index < $depth; $index++) {
        $body = $index + 1 < $depth ? 'step' . ($index + 1) . '();' : '';
        $functions[] = "function step$index(): void { $body }";
    }
    $source = <<<'PHP'
namespace App;
use Illuminate\Support\Facades\Route;
FUNCTIONS
class DeleteRequest extends \Illuminate\Foundation\Http\FormRequest {
    public function prepareForValidation(): void { step0(); }
    public function authorize(): bool { return true; }
}
class AccountController {
    public function destroy(DeleteRequest $request): void { \eraseAccounts(); }
}
Route::post('/erase', [AccountController::class, 'destroy']);
PHP;
    expect(scanLaravelAuthentication(str_replace('FUNCTIONS', implode("\n", $functions), $source))[0]['probability'])->toBe($probability);
})->with([[14, 100], [15, 80]]);
