<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89Rule;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArgPlaceholder;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;

class Cwe89RuleTestCase extends RuleTestCase
{
    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe89Rule($this->minimumProbability);
    }

    public function checkFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/../fixtures/CWE-89/cwe89.php'], $expectedErrors);
    }

    public function checkFixtureAtMinimumProbability(int $minimumProbability, array $expectedErrors): void
    {
        $this->minimumProbability = $minimumProbability;
        $this->checkFixture($expectedErrors);
    }

    public function processNodeDirectly(Node $node, ?Type $receiverType = null): array
    {
        $scope = $this->createStub(PHPStan\Analyser\Scope::class);
        $scope->method('getType')->willReturn($receiverType ?? new MixedType());

        return $this->getRule()->processNode($node, $scope);
    }
}

uses(Cwe89RuleTestCase::class);

covers(Cwe89Rule::class, RequestInput::class);

it('reports direct SQL input but not bound or numeric input', function (): void {
    $message = 'CWE-89: Request input is used in a SQL query. Use a bound parameter. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html';

    $this->checkFixture([
        [$message, 5],
        [$message, 6],
        [$message, 9],
        [$message, 10],
        [$message, 13],
        [$message, 14],
    ]);
});

it('rejects a probability minimum outside the valid range', function (): void {
    expect(fn () => new Cwe89Rule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Cwe89Rule(-1))->toThrow(InvalidArgumentException::class);
});

it('filters reports below the configured probability minimum', function (): void {
    $this->checkFixtureAtMinimumProbability(81, []);
});

it('ignores placeholder and missing query arguments', function (): void {
    $placeholderCall = new PhpParser\Node\Expr\FuncCall(
        new PhpParser\Node\Name('mysqli_query'),
        [
            new PhpParser\Node\ArgPlaceholder(),
            new PhpParser\Node\Arg(new PhpParser\Node\Expr\Variable('_GET')),
        ],
    );
    $missingQueryCall = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('mysqli_query'), []);

    expect($this->processNodeDirectly($placeholderCall))->toBe([])
        ->and($this->processNodeDirectly($missingQueryCall))->toBe([]);
});

it('recognizes supported mysqli query functions regardless of case', function (): void {
    foreach (['mysqli_query', 'mysqli_real_query', 'mysqli_multi_query', 'mysqli_prepare'] as $function) {
        $call = new FuncCall(
            new Name(strtoupper($function)),
            [new Arg(new Variable('connection')), new Arg(new Variable('_GET'))],
        );

        expect($this->processNodeDirectly($call))->toHaveCount(1);
    }
});

it('ignores dynamic and unsupported function names', function (): void {
    $dynamicCall = new FuncCall(
        new Variable('functionName'),
        [new Arg(new Variable('connection')), new Arg(new Variable('_GET'))],
    );
    $unsupportedCall = new FuncCall(
        new Name('ordinaryFunction'),
        [new Arg(new Variable('connection')), new Arg(new Variable('_GET'))],
    );

    expect($this->processNodeDirectly($dynamicCall))->toBe([])
        ->and($this->processNodeDirectly($unsupportedCall))->toBe([]);
});

it('recognizes supported PDO and mysqli query methods', function (): void {
    foreach ([
        PDO::class => ['query', 'exec', 'prepare'],
        mysqli::class => ['query', 'real_query', 'multi_query', 'prepare'],
    ] as $class => $methods) {
        foreach ($methods as $method) {
            $call = new MethodCall(
                new Variable('connection'),
                new Identifier(strtoupper($method)),
                [new Arg(new Variable('_GET'))],
            );

            expect($this->processNodeDirectly($call, new ObjectType($class)))->toHaveCount(1);
        }
    }
});

it('requires a supported query method and matching database receiver', function (): void {
    $call = new MethodCall(
        new Variable('connection'),
        new Identifier('query'),
        [new Arg(new Variable('_GET'))],
    );
    $unsupportedMethod = new MethodCall(
        new Variable('connection'),
        new Identifier('update'),
        [new Arg(new Variable('_GET'))],
    );
    $dynamicMethod = new MethodCall(
        new Variable('connection'),
        new Variable('methodName'),
        [new Arg(new Variable('_GET'))],
    );

    expect($this->processNodeDirectly($call, new ObjectType(stdClass::class)))->toBe([])
        ->and($this->processNodeDirectly($unsupportedMethod, new ObjectType(PDO::class)))->toBe([])
        ->and($this->processNodeDirectly($dynamicMethod, new ObjectType(PDO::class)))->toBe([]);
});

it('skips placeholders and matches case-insensitive named query arguments', function (): void {
    $placeholderCall = new FuncCall(
        new Name('mysqli_query'),
        [
            new ArgPlaceholder(),
            new Arg(new Variable('connection')),
            new Arg(new Variable('_GET')),
        ],
    );
    $namedArgumentCall = new FuncCall(
        new Name('mysqli_query'),
        [new Arg(new Variable('_GET'), name: new Identifier('QUERY'))],
    );

    expect($this->processNodeDirectly($placeholderCall))->toHaveCount(1)
        ->and($this->processNodeDirectly($namedArgumentCall))->toHaveCount(1);
});

it('has a default probability of 80', function (): void {
    expect(Cwe89Rule::getProbability())->toBe(80);
});

it('returns the min probability set in the constructor', function (): void {
    $rule = new Cwe89Rule(50);
    $defaultRule = new Cwe89Rule();

    expect(invade($rule)->getMinProbability())->toBe(50)
        ->and(invade($defaultRule)->getMinProbability())->toBe(0);
});
