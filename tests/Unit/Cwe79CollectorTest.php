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
        ['endTokenPos' => 20],
    );
    $event = $this->collector->processNode($assignment, $this->scope);
    expect($this->collector->getNodeType())->toBe(Node::class)
        ->and($event)->toBe([
            'kind' => 'assignment', 'scope' => '::file', 'offset' => 20,
            'variable' => 'html', 'request' => false, 'variables' => ['html', 'name'],
        ]);
    $output = new Node\Stmt\Echo_(
        [new String_('prefix'), new Expr\Variable('html')],
        ['endTokenPos' => 30, 'startLine' => 4],
    );
    expect($this->collector->processNode($output, $this->scope))->toBe([
        'kind' => 'sink', 'scope' => '::file', 'offset' => 30, 'line' => 4,
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

it('keeps direct closure checks but does not use or change outer variable facts', function (): void {
    $this->scope->method('isInAnonymousFunction')->willReturn(true);
    expect($this->collector->processNode(
        new Expr\Assign(new Expr\Variable('name'), new Expr\Variable('_GET')),
        $this->scope,
    ))->toBeNull()
        ->and($this->collector->processNode(
            new Expr\Print_(new Expr\Variable('name')),
            $this->scope,
        ))->toMatchArray(['request' => false, 'variables' => []])
        ->and($this->collector->processNode(
            new Expr\Print_(new Expr\Variable('_GET')),
            $this->scope,
        ))->toMatchArray(['request' => true, 'variables' => []]);
});
