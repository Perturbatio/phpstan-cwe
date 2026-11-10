<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe306\LaravelAuthenticationScanner;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

covers(LaravelAuthenticationScanner::class);

function chainedCallFacts(array $nodes, array $candidates = [['App\Service::execute', 'App\BaseService::execute']]): array
{
    $calls = (new NodeFinder())->find($nodes, static fn (Node $node): bool => ($node instanceof Expr\MethodCall
        || $node instanceof Expr\NullsafeMethodCall) && $node->var instanceof Expr\CallLike);

    return array_map(static fn (Node $call): array => [
        'start' => $call->getStartFilePos(), 'end' => $call->getEndFilePos(),
        'method' => $call->name->toString(), 'candidates' => $candidates, 'complete' => true,
    ], $calls);
}

it('applies collected operations only at reachable execution points', function (string $body, string $middleware, int $count): void {
    $source = '<?php use Illuminate\Support\Facades\Route; use Illuminate\Support\Facades\Auth; '
        . 'Route::post("/action", function () { ' . $body . ' })' . $middleware . ';';
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse($source);
    $scanner = new LaravelAuthenticationScanner(['App\**\Service::execute'], [], []);
    $reports = $scanner->scan(['route.php' => $nodes], ['route.php' => chainedCallFacts($nodes)]);

    expect($reports)->toHaveCount($count);
    if ($count !== 0) {
        expect($reports[0])->toBe([
            'file' => 'route.php', 'line' => 1, 'operation' => 'App\Service::execute',
            'operationLine' => 1, 'probability' => $middleware === '->middleware("unknown")' ? 40 : 80,
        ]);
    }
})->with([
    ['factory()->execute();', '', 1],
    ['factory()->execute(); factory()->execute();', '', 1],
    ['factory()->execute();', '->middleware("auth")', 0],
    ['factory()->execute();', '->middleware("auth:sanctum")', 0],
    ['factory()->execute();', '->middleware("unknown")', 1],
    ['if (!Auth::check()) { exit; } factory()->execute();', '', 0],
    ['if (!Auth::check()) { exit; } Auth::logout(); factory()->execute();', '', 1],
    ['factory(exit)->execute();', '', 0],
    ['factory()->execute(exit);', '', 0],
    ['factory()?->execute(exit);', '', 0],
    ['exit; factory()->execute();', '', 0],
    ['$callback = fn () => factory()->execute();', '', 0],
    ['$callback = function () { factory()->execute(); };', '', 0],
    ['factory()?->execute();', '', 1],
]);

it('joins facts by file and both call positions, not by line', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse('<?php use Illuminate\Support\Facades\Route; Route::post("/action", function () { factory()->execute(); factory()->execute(); });');
    $facts = chainedCallFacts($nodes);
    $scanner = new LaravelAuthenticationScanner(['App\Service::execute'], [], []);
    $second = $facts[1];
    $second['candidates'] = [['Other::execute', 'Other::execute']];
    expect($scanner->scan(['route.php' => $nodes], [
        'route.php' => [null, $second], 'other.php' => [$facts[0]],
    ]))->toBe([]);
    $wrongEnd = $facts[0];
    $wrongEnd['end']++;
    expect($scanner->scan(['route.php' => $nodes], ['route.php' => [$wrongEnd]]))->toBe([])
        ->and($scanner->scan(['route.php' => $nodes], ['route.php' => [$facts[0]]]))->toHaveCount(1)
        ->and($scanner->scan(['route.php' => $nodes]))->toBe([]);
});

it('checks exclusions across receiver and declaring identities', function (array $operations, int $count): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php use Illuminate\Support\Facades\Route; Route::post("/action", fn () => factory()->execute());');
    $reports = (new LaravelAuthenticationScanner($operations, [], []))->scan(
        ['route.php' => $nodes],
        ['route.php' => chainedCallFacts($nodes)],
    );
    expect($reports)->toHaveCount($count);
})->with([
    [['App\BaseService::execute'], 1],
    [['App\**\*::execute', '!App\Service::*'], 0],
    [['App\**\*::execute', '!App\BaseService::*'], 0],
    [['App\Models\**\*::delete'], 0],
]);

it('keeps facts available through helpers in another file', function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $routes = $parser->parse('<?php use Illuminate\Support\Facades\Route; Route::post("/action", fn () => helper());');
    $helper = $parser->parse("<?php function helper() {\n factory()->execute();\n}");
    $scanner = new LaravelAuthenticationScanner(['App\Service::execute'], [], []);
    $reports = $scanner->scan(
        ['route.php' => $routes, 'helper.php' => $helper],
        ['helper.php' => chainedCallFacts($helper)],
    );
    expect($reports)->toBe([[
        'file' => 'route.php', 'line' => 1, 'operation' => 'App\Service::execute',
        'operationLine' => 2, 'probability' => 80,
    ]]);
});

it('rejects facts for other call syntax or a different method name', function (string $call): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        '<?php use Illuminate\Support\Facades\Route; Route::post("/action", fn () => ' . $call . ');',
    );
    $calls = (new NodeFinder())->findInstanceOf($nodes, Expr\CallLike::class);
    $outerCall = $calls[1];
    $fact = [
        'start' => $outerCall->getStartFilePos(), 'end' => $outerCall->getEndFilePos(),
        'method' => 'execute', 'candidates' => [['App\Service::execute', 'App\Service::execute']], 'complete' => true,
    ];

    expect((new LaravelAuthenticationScanner(['App\Service::execute'], [], []))->scan(
        ['route.php' => $nodes],
        ['route.php' => [$fact]],
    ))->toBe([]);
})->with([
    'Other::execute()',
    'factory()->$method()',
    'factory()->different()',
]);

it('keeps a non-excluded union alternative available', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        '<?php use Illuminate\Support\Facades\Route; Route::post("/action", fn () => factory()->execute());',
    );
    $facts = chainedCallFacts($nodes, [
        ['App\Service::execute', 'App\BaseService::execute'],
        ['App\OtherService::execute', 'App\OtherService::execute'],
    ]);
    $reports = (new LaravelAuthenticationScanner(['App\**\*::execute', '!App\Service::*'], [], []))->scan(
        ['route.php' => $nodes],
        ['route.php' => $facts],
    );

    expect(array_column($reports, 'operation'))->toBe(['App\OtherService::execute'])
        ->and($reports[0]['probability'])->toBe(80);
});

it('evaluates critical receiver calls and arguments before the chained operation', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php use Illuminate\Support\Facades\Route; Route::post("/action", fn () => factory()->execute(erase()));');
    $reports = (new LaravelAuthenticationScanner(['factory', 'erase', 'App\Service::execute'], [], []))->scan(
        ['route.php' => $nodes],
        ['route.php' => chainedCallFacts($nodes)],
    );

    expect(array_column($reports, 'operation'))->toBe(['factory', 'erase', 'App\Service::execute']);
});

it('does not use a collected receiver body to establish authentication', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
namespace App;
use Illuminate\Support\Facades\Route;
class Service { public function execute() { if (!\Illuminate\Support\Facades\Auth::check()) { exit; } } }
Route::post('/action', function () { factory()->execute(); \erase(); });
PHP);
    $reports = (new LaravelAuthenticationScanner(['erase'], [], []))->scan(
        ['route.php' => $nodes],
        ['route.php' => chainedCallFacts($nodes)],
    );

    expect(array_column($reports, 'operation'))->toBe(['erase'])
        ->and($reports[0]['probability'])->toBe(80);
});
