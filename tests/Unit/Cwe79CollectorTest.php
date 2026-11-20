<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Collector;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Testing\PHPStanTestCase;
use PHPStan\Type\MixedType;

covers(Cwe79Collector::class);

class Cwe79CollectorTestCase extends PHPStanTestCase
{
}

uses(Cwe79CollectorTestCase::class);

beforeEach(function (): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(static fn (Node\Name $name): string => $name->toString());
    $this->collector = new Cwe79Collector($provider);
    $this->scope = $this->createStub(Scope::class);
    $this->scope->method('getType')->willReturn(new MixedType());
});

it('records local dependencies once with assignment and output positions', function (): void {
    $assignment = new Expr\AssignOp\Concat(
        new Expr\Variable('html'),
        new Expr\BinaryOp\Concat(new Expr\Variable('html'), new Expr\Variable('name')),
        ['startTokenPos' => 10, 'endTokenPos' => 20],
    );
    $event = $this->collector->processNode($assignment, $this->scope);
    expect($this->collector->getNodeType())->toBe(Node::class)
        ->and($event)->toBe([
            'kind' => 'assignment', 'scope' => '::file', 'offset' => 20, 'startOffset' => 10,
            'variable' => 'html', 'request' => false, 'variables' => ['html', 'name'],
        ]);
    $output = new Node\Stmt\Echo_(
        [new String_('prefix'), new Expr\Variable('html')],
        ['startTokenPos' => 25, 'endTokenPos' => 30, 'startLine' => 4],
    );
    expect($this->collector->processNode($output, $this->scope))->toBe([
        'kind' => 'sink', 'scope' => '::file', 'offset' => 30, 'startOffset' => 25, 'line' => 4,
        'expression' => "'prefix', \$html",
        'request' => false, 'variables' => ['html'],
    ]);
});

it('does not track unsupported assignment targets or other statements', function (Node $node): void {
    expect($this->collector->processNode($node, $this->scope))->toBeNull();
})->with([
    'property' => [new Expr\Assign(new Expr\PropertyFetch(new Expr\Variable('object'), 'name'), new Expr\Variable('_GET'))],
    'array item' => [new Expr\Assign(new Expr\ArrayDimFetch(new Expr\Variable('values'), new String_('name')), new Expr\Variable('_GET'))],
    'variable variable' => [new Expr\Assign(new Expr\Variable(new Expr\Variable('name')), new Expr\Variable('_GET'))],
    'return' => [new Node\Stmt\Return_(new Expr\Variable('_GET'))],
]);

it('keeps the class name before the function name in the scope key', function (): void {
    $class = $this->getContainer()->getByType(ReflectionProvider::class)->getClass(stdClass::class);
    $this->scope->method('getClassReflection')->willReturn($class);
    $this->scope->method('getFunctionName')->willReturn('render');

    $event = $this->collector->processNode(
        new Expr\Assign(new Expr\Variable('html'), new String_('fixed')),
        $this->scope,
    );

    expect($event['scope'])->toBe('stdClass::render');
});

it('returns assignment dependencies as a list after removing repeated names', function (): void {
    $expression = new Expr\BinaryOp\Concat(
        new Expr\BinaryOp\Concat(new Expr\Variable('first'), new Expr\Variable('first')),
        new Expr\Variable('second'),
    );
    $event = $this->collector->processNode(
        new Expr\Assign(new Expr\Variable('html'), $expression),
        $this->scope,
    );

    expect($event['variables'])->toBe(['first', 'second']);
});

it('returns output dependencies once as a list across echo expressions', function (): void {
    $event = $this->collector->processNode(
        new Node\Stmt\Echo_([
            new Expr\Variable('first'),
            new Expr\Variable('first'),
            new Expr\Variable('second'),
        ]),
        $this->scope,
    );

    expect($event['variables'])->toBe(['first', 'second']);
});

it('records local assignments and output dependencies inside anonymous functions', function (): void {
    $this->scope->method('isInAnonymousFunction')->willReturn(true);
    expect($this->collector->processNode(
        new Expr\Assign(new Expr\Variable('name'), new Expr\Variable('_GET')),
        $this->scope,
    ))->toMatchArray(['kind' => 'assignment', 'request' => true, 'variables' => []])
        ->and($this->collector->processNode(
            new Expr\Print_(new Expr\Variable('name')),
            $this->scope,
        ))->toMatchArray(['request' => false, 'variables' => ['name']])
        ->and($this->collector->processNode(
            new Expr\Print_(new Expr\Variable('_GET')),
            $this->scope,
        ))->toMatchArray(['request' => true, 'variables' => []]);
});

it('records closure and arrow function bounds', function (Node $node): void {
    expect($this->collector->processNode($node, $this->scope))->toBe([
        'kind' => 'scope', 'scope' => '::file', 'offset' => 10, 'endOffset' => 30,
    ]);
})->with([
    'closure' => [new Expr\Closure([], ['startTokenPos' => 10, 'endTokenPos' => 30])],
    'arrow' => [new Expr\ArrowFunction(['expr' => new Expr\Variable('value')], ['startTokenPos' => 10, 'endTokenPos' => 30])],
]);

it('does not record a concatenation as a callback assignment or copy', function (Expr $expression): void {
    $event = $this->collector->processNode(
        new Expr\AssignOp\Concat(new Expr\Variable('html'), $expression),
        $this->scope,
    );

    expect($event['request'])->toBeFalse()
        ->and($event)->not->toHaveKey('isArrow')
        ->and($event)->not->toHaveKey('copiedVariable');
})->with([
    'arrow expression' => [new Expr\ArrowFunction(['expr' => new Expr\Variable('_GET')])],
    'variable expression' => [new Expr\Variable('callback')],
]);

it('records called dependencies once and in source order', function (Closure $makeNode): void {
    $first = new Expr\FuncCall(new Expr\Variable('first'));
    $second = new Expr\FuncCall(new Expr\Variable('second'));
    $expression = new Expr\BinaryOp\Concat(new Expr\BinaryOp\Concat($first, clone $first), $second);

    $event = $this->collector->processNode($makeNode($expression), $this->scope);

    expect($event['calledVariables'])->toBe(['first', 'second'])
        ->and($event['variables'])->toBe([]);
})->with([
    'assignment' => [static fn (Expr $expr): Expr => new Expr\Assign(new Expr\Variable('html'), $expr)],
    'output' => [static fn (Expr $expr): Node => new Node\Stmt\Echo_([$expr])],
]);

it('keeps valid arrow parameters separate from captured variables after a parser error', function (): void {
    $arrow = new Expr\ArrowFunction([
        'params' => [new Node\Param(new Expr\Error()), new Node\Param(new Expr\Variable('local'))],
        'expr' => new Expr\BinaryOp\Concat(new Expr\Variable('local'), new Expr\Variable('captured')),
    ]);

    $event = $this->collector->processNode(new Expr\Assign(new Expr\Variable('callback'), $arrow), $this->scope);

    expect($event['variables'])->toBe(['captured']);
});
