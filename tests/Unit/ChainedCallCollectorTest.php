<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe306\ChainedCallCollector;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PHPStan\Analyser\Scope;
use PHPStan\Testing\PHPStanTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\IntersectionType;
use PHPStan\Type\NullType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use PHPStan\Type\UnionType;

class ChainedCallCollectorTestCase extends PHPStanTestCase
{
}

class ChainedDateTime extends DateTimeImmutable
{
}

class OverriddenChainedDateTime extends DateTimeImmutable
{
    public function modify(string $modifier): DateTimeImmutable
    {
        return parent::modify($modifier);
    }
}

interface ChainedReceiverMarker
{
}

uses(ChainedCallCollectorTestCase::class);
covers(ChainedCallCollector::class);

it('records serializable receiver and declaring identities with exact positions', function (bool $nullable): void {
    $scope = $this->createStub(Scope::class);
    $type = new ObjectType(DateTimeImmutable::class);
    $scope->method('getType')->willReturn($nullable ? new UnionType([$type, new NullType()]) : $type);
    $node = new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify', [], [
        'startFilePos' => 12, 'endFilePos' => 65,
    ]);
    $collector = new ChainedCallCollector();
    $fact = $collector->processNode($node, $scope);

    expect($collector->getNodeType())->toBe(Expr::class)
        ->and($fact)->toBe([
            'start' => 12, 'end' => 65, 'method' => 'modify',
            'candidates' => [['DateTimeImmutable::modify', 'DateTimeImmutable::modify']],
            'complete' => !$nullable,
        ])
        ->and(unserialize(serialize($fact)))->toBe($fact);
})->with([false, true]);

it('ignores unsupported call syntax', function (Node $node): void {
    $scope = $this->createMock(Scope::class);
    $scope->expects($this->never())->method('getType');
    expect((new ChainedCallCollector())->processNode($node, $scope))->toBeNull();
})->with([
    [new Expr\Variable('value')],
    [new Expr\MethodCall(new Expr\Variable('receiver'), 'modify')],
    [new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), new Expr\Variable('method'))],
    [new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify', [new Node\VariadicPlaceholder()])],
]);

it('leaves unresolved receivers and missing methods unknown', function (Type $type): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn($type);
    $node = new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify');

    expect((new ChainedCallCollector())->processNode($node, $scope))->toBeNull();
})->with([new MixedType(), new NullType(), new ObjectType(stdClass::class)]);

it('keeps unrelated union alternatives incomplete', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new UnionType([
        new ObjectType(DateTimeImmutable::class), new ObjectType(stdClass::class),
    ]));
    $node = new Expr\NullsafeMethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify');
    $fact = (new ChainedCallCollector())->processNode($node, $scope);

    expect($fact['complete'])->toBeFalse()
        ->and($fact['candidates'])->toBe([['DateTimeImmutable::modify', 'DateTimeImmutable::modify']]);
});

it('retains the declaring class of an inherited method', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new ObjectType(ChainedDateTime::class));
    $fact = (new ChainedCallCollector())->processNode(
        new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify'),
        $scope,
    );

    expect($fact['candidates'])->toBe([['ChainedDateTime::modify', 'DateTimeImmutable::modify']])
        ->and($fact['complete'])->toBeTrue();
});

it('records each resolved union alternative without claiming complete evidence', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new UnionType([
        new ObjectType(DateTime::class), new ObjectType(DateTimeImmutable::class),
    ]));
    $fact = (new ChainedCallCollector())->processNode(
        new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify'),
        $scope,
    );

    expect($fact['complete'])->toBeFalse()
        ->and($fact['candidates'])->toHaveCount(2);
});

it('uses the child declaration for an overridden method', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new ObjectType(OverriddenChainedDateTime::class));
    $fact = (new ChainedCallCollector())->processNode(
        new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify'),
        $scope,
    );

    expect($fact['candidates'])->toBe([['OverriddenChainedDateTime::modify', 'OverriddenChainedDateTime::modify']]);
});

it('preserves the method identity in an intersection type', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new IntersectionType([
        new ObjectType(DateTimeImmutable::class), new ObjectType(ChainedReceiverMarker::class),
    ]));
    $fact = (new ChainedCallCollector())->processNode(
        new Expr\MethodCall(new Expr\FuncCall(new Node\Name('factory')), 'modify'),
        $scope,
    );

    expect($fact['candidates'])->toBe([['DateTimeImmutable::modify', 'DateTimeImmutable::modify']]);
});
