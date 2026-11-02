<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89Rule;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

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

    public function processNodeDirectly(Node $node): array
    {
        return $this->getRule()->processNode($node, $this->createStub(PHPStan\Analyser\Scope::class));
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

it('has a default probability of 80', function (): void {
    expect(Cwe89Rule::getProbability())->toBe(80);
});

it('returns the min probability set in the constructor', function (): void {
    $rule = new Cwe89Rule(50);
    expect(invade($rule)->getMinProbability())->toBe(50);
});

it('uses zero as the default minimum probability', function (): void {
    expect(invade(new Cwe89Rule())->getMinProbability())->toBe(0);
});

it('reports each SQL sink with request input', function (string $kind, string $method, string $argumentName): void {
    $arguments = [
        new PhpParser\Node\ArgPlaceholder(),
        new PhpParser\Node\Arg(new PhpParser\Node\Expr\Variable('_GET'), name: new PhpParser\Node\Identifier(strtoupper($argumentName))),
    ];
    $scope = $this->createStub(PHPStan\Analyser\Scope::class);
    if ($kind === 'function') {
        $node = new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name(strtoupper($method)), $arguments);
    } else {
        $node = new PhpParser\Node\Expr\MethodCall(new PhpParser\Node\Expr\Variable('connection'), strtoupper($method), $arguments);
        $scope->method('getType')->willReturn(new PHPStan\Type\ObjectType($kind));
    }
    $errors = (new Cwe89Rule(80))->processNode($node, $scope);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe89')
        ->and($errors[0]->getMessage())->toBe('CWE-89: Request input is used in a SQL query. Use a bound parameter. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html');
})->with([
    'mysqli query function' => ['function', 'mysqli_query', 'query'],
    'mysqli real query function' => ['function', 'mysqli_real_query', 'query'],
    'mysqli multi query function' => ['function', 'mysqli_multi_query', 'query'],
    'mysqli prepare function' => ['function', 'mysqli_prepare', 'query'],
    'PDO query' => ['PDO', 'query', 'query'],
    'PDO exec' => ['PDO', 'exec', 'statement'],
    'PDO prepare' => ['PDO', 'prepare', 'query'],
    'mysqli query' => ['mysqli', 'query', 'query'],
    'mysqli real query' => ['mysqli', 'real_query', 'query'],
    'mysqli multi query' => ['mysqli', 'multi_query', 'query'],
    'mysqli prepare' => ['mysqli', 'prepare', 'query'],
]);

it('ignores calls that are not supported SQL sinks', function (): void {
    $scope = $this->createStub(PHPStan\Analyser\Scope::class);
    $scope->method('getType')->willReturn(new PHPStan\Type\ObjectType('stdClass'));
    $input = new PhpParser\Node\Arg(new PhpParser\Node\Expr\Variable('_GET'));
    foreach ([
        new PhpParser\Node\Expr\ConstFetch(new PhpParser\Node\Name('mysqli_query')),
        new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Expr\Variable('mysqli_query'), [$input]),
        new PhpParser\Node\Expr\FuncCall(new PhpParser\Node\Name('ordinary'), [$input]),
        new PhpParser\Node\Expr\MethodCall(new PhpParser\Node\Expr\Variable('object'), 'query', [$input]),
        new PhpParser\Node\Expr\MethodCall(new PhpParser\Node\Expr\Variable('object'), new PhpParser\Node\Expr\Variable('method'), [$input]),
    ] as $node) {
        expect((new Cwe89Rule())->processNode($node, $scope))->toBe([]);
    }
});
