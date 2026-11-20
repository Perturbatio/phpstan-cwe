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
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\Constant\ConstantIntegerType;
use PHPStan\Type\Constant\ConstantStringType;
use PHPStan\Type\MixedType;

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

it('checks assigned input without bypassing HTML protections', function (Node $node, bool $hasInput): void {
    $scope = $this->createStub(Scope::class);
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturn('htmlspecialchars');

    expect(RequestInput::inHtml(
        $node,
        $scope,
        $provider,
        static fn (string $variable): bool => $variable === 'input',
    ))->toBe($hasInput);
})->with([
    'assigned input' => [new Variable('input'), true],
    'unknown variable' => [new Variable('other'), false],
    'concatenation' => [new Expr\BinaryOp\Concat(new Variable('other'), new Variable('input')), true],
    'integer cast' => [new Expr\Cast\Int_(new Variable('input')), false],
    'float cast' => [new Expr\Cast\Double(new Variable('input')), false],
    'escape' => [new FuncCall(new Name('htmlspecialchars'), [new Arg(new Variable('input'))]), false],
]);

it('does not treat an anonymous function body as its HTML value', function (Expr $expression): void {
    $scope = $this->createStub(Scope::class);
    $provider = $this->createStub(ReflectionProvider::class);
    $variables = [];

    expect(RequestInput::inHtml(
        new Expr\Array_([new ArrayItem($expression)]),
        $scope,
        $provider,
        static function (string $variable) use (&$variables): bool {
            $variables[] = $variable;

            return false;
        },
    ))->toBeFalse()
        ->and($variables)->toBe([])
        ->and(RequestInput::inSql($expression))->toBeTrue();
})->with([
    'closure' => [new Expr\Closure(['stmts' => [new Node\Stmt\Echo_([new Variable('_GET'), new Variable('local')])]])],
    'arrow' => [new Expr\ArrowFunction(['expr' => new Expr\BinaryOp\Concat(new Variable('_GET'), new Variable('local'))])],
]);

it('checks only returned input for directly invoked anonymous functions', function (string $expression, bool $hasInput): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $expression . ';');
    $scope = $this->createStub(Scope::class);
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(static fn (Name $name): string => $name->toString());

    expect(RequestInput::inHtml(
        $nodes[0]->expr,
        $scope,
        $provider,
        static fn (string $variable): bool => $variable === 'outer',
    ))->toBe($hasInput);
})->with([
    'arrow returns input' => ['(fn () => $_GET["name"])()', true],
    'closure returns input' => ['(function () { return $_POST["name"]; })()', true],
    'branch returns input' => ['(function () { if (true) { return $_GET["name"]; } return "fixed"; })()', true],
    'else branch returns input' => ['(function () { if (true) {} else { return $_GET["name"]; } })()', true],
    'else branch returns fixed value' => ['(function () { if (true) {} else { return "fixed"; } })()', false],
    'nested call' => ['(fn () => (fn () => $_GET["name"])())()', true],
    'escaped arrow' => ['(fn () => htmlspecialchars($_GET["name"]))()', false],
    'escaped closure' => ['(function () { return htmlentities($_GET["name"]); })()', false],
    'numeric return' => ['(function () { return (int) $_GET["name"]; })()', false],
    'unused input' => ['(function () { $_GET["name"]; return "fixed"; })()', false],
    'empty return' => ['(function () { return; })()', false],
    'nested closure' => ['(function () { $f = function () { return $_GET["name"]; }; return "fixed"; })()', false],
    'nested function' => ['(function () { function nested() { return $_GET["name"]; } return "fixed"; })()', false],
    'nested class' => ['(function () { $x = new class { function value() { return $_GET["name"]; } }; return "fixed"; })()', false],
    'captured outer value' => ['(fn () => $outer)()', true],
    'parameter shadows outer value' => ['(function ($outer) { return $outer; })("fixed")', false],
    'input argument' => ['(fn ($value) => $value)($_GET["name"])', true],
    'first class callable' => ['(fn () => $_GET["name"])(...)', false],
    'inner print returns integer' => ['(fn () => print $_GET["name"])()', false],
]);

it('accepts explicit HTML escape arguments only when their values are known and safe', function (
    string $expression,
    bool $hasInput,
): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $expression . ';');
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturnCallback(static function (Node $node): PHPStan\Type\Type {
        if ($node instanceof Expr\ConstFetch && $node->name->toString() === 'ENT_QUOTES') {
            return new ConstantIntegerType(ENT_QUOTES);
        }
        if ($node instanceof Expr\ConstFetch && $node->name->toString() === 'ENT_NOQUOTES') {
            return new ConstantIntegerType(ENT_NOQUOTES);
        }
        if ($node instanceof Node\Scalar\String_) {
            return new ConstantStringType($node->value);
        }

        return new MixedType();
    });
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturn('htmlspecialchars');

    expect(RequestInput::inHtml($nodes[0]->expr, $scope, $provider))->toBe($hasInput);
})->with([
    'quotes and UTF-8' => ['htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8")', false],
    'named arguments' => ['htmlspecialchars(encoding: "utf-8", string: $_GET["name"], flags: ENT_QUOTES)', false],
    'unsafe flags' => ['htmlspecialchars($_GET["name"], ENT_NOQUOTES)', true],
    'unknown flags' => ['htmlspecialchars($_GET["name"], $flags)', true],
    'unknown encoding' => ['htmlspecialchars($_GET["name"], ENT_QUOTES, $encoding)', true],
    'invalid encoding' => ['htmlspecialchars($_GET["name"], ENT_QUOTES, "invalid")', true],
    'unpacked argument' => ['htmlspecialchars($_GET["name"], ...$flags)', true],
    'unknown named argument' => ['htmlspecialchars(invalid: $_GET["name"])', true],
    'duplicate argument' => ['htmlspecialchars(string: $_GET["name"], string: "fixed")', true],
    'missing string argument' => ['htmlspecialchars(flags: $_GET["name"])', true],
]);

it('checks called input callbacks and their arguments', function (string $expression, bool $hasInput): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse('<?php ' . $expression . ';');
    $scope = $this->createStub(Scope::class);
    $provider = $this->createStub(ReflectionProvider::class);

    expect(RequestInput::inHtml(
        $nodes[0]->expr,
        $scope,
        $provider,
        null,
        static fn (string $variable): bool => $variable === 'tainted',
    ))->toBe($hasInput);
})->with([
    'called input' => ['$tainted()', true],
    'unknown callback' => ['$other()', false],
    'input argument' => ['$other($_GET["name"])', true],
    'first class callable' => ['$tainted(...)', false],
    'captured callback' => ['(fn () => $tainted())()', true],
    'shadowed callback' => ['(fn ($tainted) => $tainted())("fixed")', false],
]);
