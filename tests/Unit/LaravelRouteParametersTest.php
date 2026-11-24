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
    'upper case method' => ["Route::GET('/{page}', fn (\$page) => \$page);", ['page']],
    'put route' => ["Route::put('/{page}', fn (\$page) => \$page);", ['page']],
    'patch route' => ["Route::patch('/{page}', fn (\$page) => \$page);", ['page']],
    'delete route' => ["Route::delete('/{page}', fn (\$page) => \$page);", ['page']],
    'options route' => ["Route::options('/{page}', fn (\$page) => \$page);", ['page']],
    'any route' => ["Route::any('/{page}', fn (\$page) => \$page);", ['page']],
    'extra scalar parameter' => ["Route::get('/{page}', fn (\$page, \$extra) => \$page);", ['page']],
    'two positional parameters' => ["Route::get('/{first}/{second}', fn (\$one, \$two, \$extra) => \$one);", ['one', 'two']],
    'more named parameters after positional parameters' => ["Route::get('/{first}', fn (\$one, \$first, \$extra) => \$one);", ['one', 'first']],
    'named arguments' => ["Route::get(action: fn (\$page) => \$page, uri: '/{page}');", ['page']],
    'no parameters' => ["Route::get('/fixed', fn (\$page) => \$page);", []],
    'unrelated facade' => ["Other::get('/{page}', fn (\$page) => \$page);", []],
    'unrelated method' => ["Route::group('/{page}', fn (\$page) => \$page);", []],
    'dynamic uri' => ['Route::get($uri, fn ($page) => $page);', []],
    'named handler' => ["Route::get('/{page}', 'Controller@show');", []],
    'unpacked arguments' => ['Route::get(...$args);', []],
    'unpacked extra argument' => ['Route::get("/{page}", fn ($page) => $page, ...$args);', []],
    'unrelated named arguments' => ['Route::get(uri: "/{page}", other: fn ($page) => $page);', []],
    'first class callable' => ['Route::get(...);', []],
    'dynamic method' => ['Route::$method("/{page}", fn ($page) => $page);', []],
    'dynamic class' => ['$route::get("/{page}", fn ($page) => $page);', []],
]);

it('skips invalid or dynamic closure parameter names', function (Error|Variable $variable): void {
    $scope = test()->createStub(Scope::class);
    $scope->method('resolveName')->willReturn('Illuminate\Support\Facades\Route');
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php Route::get("/{page}", function ($invalid, $page) {});',
    );
    $call = $nodes[0]->expr;
    $call->args[1]->value->params[0]->var = $variable;

    expect(LaravelRouteParameters::fromCall($call, $scope))->toBe([
        ['variable' => 'page', 'offset' => $call->args[1]->value->params[1]->getStartTokenPos()],
    ]);
})->with([
    'parser error' => [new Error()],
    'dynamic name' => [new Variable(new Variable('name'))],
]);
