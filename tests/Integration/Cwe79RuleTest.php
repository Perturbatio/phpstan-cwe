<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Collector;
use Perturbatio\PhpstanCwe\RequestInput;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe79RuleTestCase extends RuleTestCase
{
    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe79Rule($this->minimumProbability);
    }

    protected function getCollectors(): array
    {
        return [new Cwe79Collector($this->getContainer()->getByType(ReflectionProvider::class))];
    }

    public function checkFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/../fixtures/CWE-79/cwe79.php'], $expectedErrors);
    }

    public function checkNamespacedFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/../fixtures/CWE-79/cwe79-namespaced.php'], $expectedErrors);
    }

    public function makeRule(int $minimumProbability): Cwe79Rule
    {
        return new Cwe79Rule($minimumProbability);
    }

    public function checkFixtureAtMinimumProbability(int $minimumProbability, array $expectedErrors): void
    {
        $this->minimumProbability = $minimumProbability;
        $this->checkFixture($expectedErrors);
    }

    public function checkAssignmentsFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/../fixtures/CWE-79/assignments.php'], $expectedErrors);
    }
}

uses(Cwe79RuleTestCase::class);

covers(Cwe79Rule::class, Cwe79Collector::class, RequestInput::class);

it('reports direct HTML output but not escaped or numeric output', function (): void {
    $message = 'CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html';

    $this->checkFixture([
        [$message, 3],
        [$message, 5],
        [$message, 6],
        [$message, 8],
        [$message, 10],
    ]);
});

it('tracks local values through modifications without losing escape or scope checks', function (): void {
    $message = 'CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html';
    $this->checkAssignmentsFixture(array_map(
        static fn (int $line): array => [$message, $line],
        [6, 8, 11, 13, 15, 19, 29, 31, 34, 39, 52, 65, 71, 73],
    ));
});

it('keeps findings at the minimum probability', function (): void {
    $message = 'CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html';
    $this->checkFixtureAtMinimumProbability(80, array_map(
        static fn (int $line): array => [$message, $line],
        [3, 5, 6, 8, 10],
    ));
});

it('rejects a probability minimum outside the valid range', function (): void {
    expect(fn () => $this->makeRule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $this->makeRule(-1))->toThrow(InvalidArgumentException::class);
});

it('filters reports below the configured probability minimum', function (): void {
    $this->checkFixtureAtMinimumProbability(81, []);
});

it('uses a default probability of 80', function (): void {
    expect(Cwe79Rule::getProbability())->toBe(80);
});

it('does not trust a custom function with an HTML escape function name', function (): void {
    $this->checkNamespacedFixture([
        ['CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html', 10],
    ]);
});

it('uses zero as the default minimum and ignores empty collected data', function (): void {
    $rule = new Cwe79Rule();
    expect(invade($rule)->minProbability)->toBe(0)
        ->and($rule->getNodeType())->toBe(PHPStan\Node\CollectedDataNode::class)
        ->and($rule->processNode(new PHPStan\Node\CollectedDataNode([], false), $this->createStub(PHPStan\Analyser\Scope::class)))->toBe([]);
});

it('keeps the report metadata and source location for assigned input', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-79/cwe79.php';
    $node = new PHPStan\Node\CollectedDataNode([
        $file => [Cwe79Collector::class => [
            ['kind' => 'assignment', 'scope' => 'file', 'offset' => 10, 'variable' => 'name', 'request' => true, 'variables' => []],
            ['kind' => 'sink', 'scope' => 'file', 'offset' => 20, 'line' => 10, 'request' => false, 'variables' => ['name']],
        ]],
    ], false);
    $errors = (new Cwe79Rule())->processNode($node, $this->createStub(PHPStan\Analyser\Scope::class));

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe79')
        ->and($errors[0]->getFile())->toBe($file)
        ->and($errors[0]->getLine())->toBe(10)
        ->and($errors[0]->getMetadata())->toBe([
            'cwe' => 79, 'severity' => 'high', 'probability' => 80,
            'url' => 'https://cwe.mitre.org/data/definitions/79.html',
        ]);
});
