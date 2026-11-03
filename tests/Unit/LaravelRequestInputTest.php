<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Rule;
use Perturbatio\PhpstanCwe\LaravelRequestInput;
use Perturbatio\PhpstanCwe\RequestInput;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelCollector;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\VariadicPlaceholder;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\NullType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\UnionType;

class LaravelRequestInputTestCase extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new Cwe78Rule();
    }
}

uses(LaravelRequestInputTestCase::class);

covers(LaravelRequestInput::class, Cwe78Collector::class, RequestInput::class, Cwe89LaravelCollector::class);

beforeEach(function (): void {
    $this->reflectionProvider = $this->createStub(ReflectionProvider::class);
    $this->reflectionProvider->method('resolveFunctionName')->willReturnCallback(
        static fn (Name $name): string => $name->toString(),
    );
    $this->scope = $this->createStub(Scope::class);
    $this->scope->method('getType')->willReturn(new ObjectType('Illuminate\Http\Request'));
    $this->scope->method('getFile')->willReturn('/tmp/laravel-command.php');
    $this->requestInput = new LaravelRequestInput($this->reflectionProvider);
});

it('recognizes input methods on typed request objects', function (string $method): void {
    $call = new Expr\MethodCall(
        new Expr\Variable('incomingRequest'),
        new Identifier(strtoupper($method)),
        [new Arg(new String_('command'))],
    );

    expect($this->requestInput->isInput($call, $this->scope))->toBeTrue()
        ->and(RequestInput::inHtml($call, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inSql($call, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and((new Cwe89LaravelCollector($this->reflectionProvider))->processNode(
            new Expr\Assign(new Expr\Variable('value'), $call),
            $this->scope,
        ))->toMatchArray(['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []]);
})->with([
    'input', 'get', 'query', 'post', 'cookie', 'header', 'server', 'all',
    'only', 'except', 'json', 'collect', 'string', 'str', 'route',
    'validated', 'safe', 'bearerToken', 'getContent',
]);

it('recognizes request object property, array, and nullsafe input reads', function (Node $node): void {
    expect($this->requestInput->isInput($node, $this->scope))->toBeTrue()
        ->and(RequestInput::inHtml($node, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inSql($node, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and((new Cwe89LaravelCollector($this->reflectionProvider))->processNode(
            new Expr\Assign(new Expr\Variable('value'), $node),
            $this->scope,
        ))->toMatchArray(['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []]);
})->with([
    'property' => [new Expr\PropertyFetch(new Expr\Variable('request'), 'command')],
    'dynamic property' => [new Expr\PropertyFetch(new Expr\Variable('request'), new Expr\Variable('key'))],
    'nullsafe property' => [new Expr\NullsafePropertyFetch(new Expr\Variable('request'), 'command')],
    'array' => [new Expr\ArrayDimFetch(new Expr\Variable('request'), new String_('command'))],
    'nullsafe method' => [new Expr\NullsafeMethodCall(new Expr\Variable('request'), 'input')],
]);

it('recognizes global request helper calls with positional or named input keys', function (array $arguments): void {
    $call = new Expr\FuncCall(new Name('REQUEST'), $arguments);

    expect($this->requestInput->isInput($call, $this->scope))->toBeTrue()
        ->and(RequestInput::inHtml($call, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inSql($call, $this->scope, $this->reflectionProvider))->toBeTrue();
})->with([
    'positional' => [[new Arg(new String_('command'))]],
    'named' => [[new Arg(new String_('command'), name: new Identifier('key'))]],
]);

it('recognizes input reads on the request helper without receiver type information', function (Node $node): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new MixedType());

    expect($this->requestInput->isInput($node, $scope))->toBeTrue()
        ->and(RequestInput::inHtml($node, $scope, $this->reflectionProvider))->toBeTrue();
})->with([
    'method' => [new Expr\MethodCall(new Expr\FuncCall(new Name('request')), 'input')],
    'property' => [new Expr\PropertyFetch(new Expr\FuncCall(new Name('request')), 'command')],
    'array' => [new Expr\ArrayDimFetch(new Expr\FuncCall(new Name('request')), new String_('command'))],
]);

it('supports nullable typed request receivers', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new UnionType([
        new ObjectType('Illuminate\Http\Request'),
        new NullType(),
    ]));

    expect($this->requestInput->isInput(
        new Expr\NullsafeMethodCall(new Expr\Variable('request'), 'input'),
        $scope,
    ))->toBeTrue();
});

it('does not classify unrelated nodes, methods, or callable references as input', function (Node $node): void {
    expect($this->requestInput->isInput($node, $this->scope))->toBeFalse();
})->with([
    'literal' => [new String_('command')],
    'variable' => [new Expr\Variable('request')],
    'request object helper' => [new Expr\FuncCall(new Name('request'))],
    'different helper' => [new Expr\FuncCall(new Name('other'), [new Arg(new String_('command'))])],
    'dynamic helper' => [new Expr\FuncCall(new Expr\Variable('request'), [new Arg(new String_('command'))])],
    'helper reference' => [new Expr\FuncCall(new Name('request'), [new VariadicPlaceholder()])],
    'method reference' => [new Expr\MethodCall(new Expr\Variable('request'), 'input', [new VariadicPlaceholder()])],
    'dynamic method' => [new Expr\MethodCall(new Expr\Variable('request'), new Expr\Variable('method'))],
    'HTTP method' => [new Expr\MethodCall(new Expr\Variable('request'), 'method')],
    'path' => [new Expr\MethodCall(new Expr\FuncCall(new Name('request')), 'path')],
]);

it('does not identify shadowed or unresolved helpers by name alone', function (?string $resolvedFunction): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturn($resolvedFunction);
    $requestInput = new LaravelRequestInput($provider);

    $call = new Expr\FuncCall(new Name('request'), [new Arg(new String_('command'))]);

    expect($requestInput->isInput($call, $this->scope))->toBeFalse()
        ->and(RequestInput::inHtml($call, $this->scope, $provider))->toBeFalse()
        ->and(RequestInput::inSql($call, $this->scope, $provider))->toBeFalse()
        ->and((new Cwe89LaravelCollector($provider))->processNode(
            new Expr\Assign(new Expr\Variable('value'), $call),
            $this->scope,
        ))->toMatchArray(['dynamic' => true, 'request' => false, 'unknown' => true]);
})->with(['shadowed' => ['App\request'], 'unknown' => [null]]);

it('does not identify unknown receivers or helper values as request objects', function (Expr $receiver): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new MixedType());

    expect($this->requestInput->isInput(new Expr\MethodCall($receiver, 'input'), $scope))->toBeFalse();
})->with([
    'untyped object' => [new Expr\Variable('request')],
    'other helper' => [new Expr\FuncCall(new Name('other'))],
    'helper input value' => [new Expr\FuncCall(new Name('request'), [new Arg(new String_('key'))])],
    'helper reference' => [new Expr\FuncCall(new Name('request'), [new VariadicPlaceholder()])],
]);

it('adds Laravel input facts only when the variant is enabled and preserves shell argument protection', function (): void {
    $input = new Expr\MethodCall(new Expr\Variable('request'), 'input', [new Arg(new String_('command'))]);
    $command = new Expr\FuncCall(new Name('exec'), [new Arg($input)]);
    $collector = new Cwe78Collector($this->reflectionProvider, $this->requestInput);
    $baseCollector = new Cwe78Collector($this->reflectionProvider);

    expect($collector->processNode($command, $this->scope))->toMatchArray([
        'request' => true,
        'hasStaticText' => false,
        'variables' => [],
    ])
        ->and($baseCollector->processNode($command, $this->scope)['request'])->toBeFalse()
        ->and($collector->processNode(
            new Expr\FuncCall(new Name('exec'), [
                new Arg(new Expr\FuncCall(new Name('escapeshellarg'), [new Arg($input)])),
            ]),
            $this->scope,
        ))->toMatchArray(['request' => false, 'hasStaticText' => false, 'variables' => []])
        ->and($collector->processNode(
            new Expr\Assign(new Expr\Variable('command'), $input),
            $this->scope,
        ))->toMatchArray(['kind' => 'assignment', 'request' => true, 'variable' => 'command']);
});

it('keeps HTML protections separate from command protections for Laravel input', function (): void {
    $input = new Expr\FuncCall(new Name('request'), [new Arg(new String_('name'))]);
    $htmlEscape = new Expr\FuncCall(new Name('htmlspecialchars'), [new Arg($input)]);
    $shellEscape = new Expr\FuncCall(new Name('escapeshellarg'), [new Arg($input)]);
    $collector = new Cwe78Collector($this->reflectionProvider, $this->requestInput);

    expect(RequestInput::inHtml($htmlEscape, $this->scope, $this->reflectionProvider))->toBeFalse()
        ->and(RequestInput::inHtml($shellEscape, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inHtml(new Expr\Cast\Int_($input), $this->scope, $this->reflectionProvider))->toBeFalse()
        ->and(RequestInput::inHtml(new Expr\Cast\Double($input), $this->scope, $this->reflectionProvider))->toBeFalse()
        ->and($collector->processNode(
            new Expr\FuncCall(new Name('exec'), [new Arg($htmlEscape)]),
            $this->scope,
        ))->toMatchArray(['request' => true])
        ->and($collector->processNode(
            new Expr\FuncCall(new Name('exec'), [new Arg($shellEscape)]),
            $this->scope,
        ))->toMatchArray(['request' => false])
        ->and(RequestInput::inSql($input))->toBeFalse()
        ->and(RequestInput::inSql($input, $this->scope))->toBeFalse()
        ->and(RequestInput::inSql($htmlEscape, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inSql($shellEscape, $this->scope, $this->reflectionProvider))->toBeTrue()
        ->and(RequestInput::inSql(new Expr\Cast\Int_($input), $this->scope, $this->reflectionProvider))->toBeFalse()
        ->and(RequestInput::inSql(new Expr\Cast\Double($input), $this->scope, $this->reflectionProvider))->toBeFalse();
});
