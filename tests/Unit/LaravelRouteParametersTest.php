<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\LaravelRouteParameters;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Error;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;

covers(LaravelRouteParameters::class);

it('finds parameters supplied to Laravel route closures', function (string $code, array $expected): void {
    $scope = test()->createStub(Scope::class);
    $scope->method('resolveName')->willReturnCallback(static fn (Name $name): string => $name->toString() === 'Route'
        ? 'Illuminate\Support\Facades\Route'
        : $name->toString());
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php ' . $code);
    $call = $nodes[0]->expr;
    expect($call)->toBeInstanceOf(StaticCall::class)
        ->and(array_column(LaravelRouteParameters::fromCall($call, $scope), 'variable'))->toBe($expected);
})->with([
    'named parameter' => ["Route::get('/{page}', function (string \$page) {});", ['page']],
    'positional parameter' => ["Route::post('/{page}', fn (string \$file) => \$file);", ['file']],
    'injected object' => ["Route::get('/{page}', function (Request \$request, string \$page) {});", ['page']],
    'optional and bound parameters' => ["Route::get('/{page?}/{item:slug}', function (\$page, Item \$item) {});", ['page', 'item']],
    'match route' => ["Route::match(['GET'], '/{page}', fn (\$page) => \$page);", ['page']],
    'named arguments' => ["Route::get(action: fn (\$page) => \$page, uri: '/{page}');", ['page']],
    'no parameters' => ["Route::get('/fixed', fn (\$page) => \$page);", []],
    'unrelated facade' => ["Other::get('/{page}', fn (\$page) => \$page);", []],
    'unrelated method' => ["Route::group('/{page}', fn (\$page) => \$page);", []],
    'dynamic uri' => ['Route::get($uri, fn ($page) => $page);', []],
    'named handler' => ["Route::get('/{page}', 'Controller@show');", []],
    'unpacked arguments' => ['Route::get(...$args);', []],
    'first class callable' => ['Route::get(...);', []],
    'dynamic method' => ['Route::$method("/{page}", fn ($page) => $page);', []],
    'dynamic class' => ['$route::get("/{page}", fn ($page) => $page);', []],
]);

it('skips invalid or dynamic closure parameter names', function (Error|Variable $variable): void {
    $scope = test()->createStub(Scope::class);
    $scope->method('resolveName')->willReturn('Illuminate\Support\Facades\Route');
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php Route::get("/{page}", function ($page) {});',
    );
    $call = $nodes[0]->expr;
    $call->args[1]->value->params[0]->var = $variable;

    expect(LaravelRouteParameters::fromCall($call, $scope))->toBe([]);
})->with([
    'parser error' => [new Error()],
    'dynamic name' => [new Variable(new Variable('name'))],
]);
