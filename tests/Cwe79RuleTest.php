<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe79Rule;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe79RuleTestCase extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new Cwe79Rule($this->getContainer()->getByType(ReflectionProvider::class));
    }

    public function checkFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/fixtures/cwe79.php'], $expectedErrors);
    }

    public function checkNamespacedFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/fixtures/cwe79-namespaced.php'], $expectedErrors);
    }

    public function makeRule(int $minimumProbability): Cwe79Rule
    {
        return new Cwe79Rule($this->getContainer()->getByType(ReflectionProvider::class), $minimumProbability);
    }
}

uses(Cwe79RuleTestCase::class);

it('reports direct HTML output but not escaped or numeric output', function (): void {
    $message = 'CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html';

    $this->checkFixture([
        [$message, 3],
        [$message, 5],
        [$message, 6],
        [$message, 8],
    ]);
});

it('rejects a probability minimum outside the valid range', function (): void {
    expect(fn() => $this->makeRule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn() => $this->makeRule(-1))->toThrow(InvalidArgumentException::class);
});

it('does not trust a custom function with an HTML escape function name', function (): void {
    $this->checkNamespacedFixture([
        ['CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html', 10],
    ]);
});
