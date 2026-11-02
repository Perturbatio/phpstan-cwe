<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

covers(RequestInput::class);

it('finds request input in child nodes but not in numeric casts or node names', function (Node $node, bool $hasInput): void {
    expect(RequestInput::inSql($node))->toBe($hasInput);
})->with([
    'get' => [new Variable('_GET'), true],
    'post' => [new Variable('_POST'), true],
    'cookie' => [new Variable('_COOKIE'), true],
    'request' => [new Variable('_REQUEST'), true],
    'ordinary variable' => [new Variable('value'), false],
    'identifier' => [new Identifier('_GET'), false],
    'integer cast' => [new Expr\Cast\Int_(new Variable('_GET')), false],
    'float cast' => [new Expr\Cast\Double(new Variable('_GET')), false],
    'array with empty item' => [new Expr\Array_([null, new ArrayItem(new Variable('_GET'))]), true],
    'empty array item' => [new Expr\Array_([null]), false],
    'static array' => [new Expr\Array_([new ArrayItem(new Variable('value'))]), false],
    'nested input' => [new Expr\BinaryOp\Concat(new Variable('value'), new Variable('_POST')), true],
]);

it('accepts only recognised default HTML escape calls', function (
    Name|Expr $name,
    array $arguments,
    ?string $namespace,
    ?string $resolvedName,
    bool $hasInput,
): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getNamespace')->willReturn($namespace);
    $reflectionProvider = $this->createStub(ReflectionProvider::class);
    $reflectionProvider->method('resolveFunctionName')->willReturn($resolvedName);
    $call = new FuncCall($name, $arguments);

    expect(RequestInput::inHtml($call, $scope, $reflectionProvider))->toBe($hasInput)
        ->and(RequestInput::inSql($call))->toBeTrue();
})->with([
    'htmlspecialchars' => [new Name('htmlspecialchars'), [new Arg(new Variable('_GET'))], null, 'htmlspecialchars', false],
    'htmlentities' => [new Name('htmlentities'), [new Arg(new Variable('_GET'))], null, 'htmlentities', false],
    'upper case' => [new Name('HTMLENTITIES'), [new Arg(new Variable('_GET'))], null, 'HTMLENTITIES', false],
    'qualified escape' => [new Name\FullyQualified('htmlentities'), [new Arg(new Variable('_GET'))], 'App', 'htmlentities', false],
    'namespace shadow' => [new Name('htmlentities'), [new Arg(new Variable('_GET'))], 'App', 'App\\htmlentities', true],
    'unknown function' => [new Name('unknown'), [new Arg(new Variable('_GET'))], null, null, true],
    'dynamic function' => [new Variable('escape'), [new Arg(new Variable('_GET'))], null, 'htmlentities', true],
    'nondefault flags' => [new Name('htmlentities'), [new Arg(new Variable('_GET')), new Arg(new Variable('flags'))], null, 'htmlentities', true],
]);
