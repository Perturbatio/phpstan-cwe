<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Collector;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\MixedType;

covers(Cwe79Collector::class);

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
    'variable variable' => [new Expr\Assign(new Expr\Variable(new Expr\Variable('name')), new Expr\Variable('_GET'))],
    'return' => [new Node\Stmt\Return_(new Expr\Variable('_GET'))],
]);

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
