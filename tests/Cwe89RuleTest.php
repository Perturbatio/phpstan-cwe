<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89Rule;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe89RuleTestCase extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new Cwe89Rule();
    }

    public function checkFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/fixtures/cwe89.php'], $expectedErrors);
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
