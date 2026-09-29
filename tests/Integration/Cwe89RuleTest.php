<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89Rule;
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
        return $this->getRule()->processNode($node, $this->createMock(PHPStan\Analyser\Scope::class));
    }
}

uses(Cwe89RuleTestCase::class);

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
    expect(fn() => new Cwe89Rule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn() => new Cwe89Rule(-1))->toThrow(InvalidArgumentException::class);
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
