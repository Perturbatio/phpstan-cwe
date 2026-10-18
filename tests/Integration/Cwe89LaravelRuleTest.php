<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89LaravelRule;
use Perturbatio\PhpstanCwe\Rules\Cwe89LaravelCollector;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe89LaravelRuleTestCase extends RuleTestCase
{
    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe89LaravelRule($this->minimumProbability);
    }

    public function processFindingsAtMinimumProbability(int $minimumProbability, array $events): array
    {
        $this->minimumProbability = $minimumProbability;
        $collectedData = [];
        foreach ($events as $event) {
            $collectedData[$event['file']][Cwe89LaravelCollector::class][] = $event;
        }
        $node = new CollectedDataNode($collectedData, false);

        return $this->getRule()->processNode($node, $this->createMock(Scope::class));
    }
}

uses(Cwe89LaravelRuleTestCase::class);

it('reports a known request source traced through a local assignment', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-89/laravel.php';
    $assignment = [
        'kind' => 'assignment',
        'file' => $file,
        'scope' => 'example',
        'offset' => 10,
        'variable' => 'user',
        'dynamic' => true,
        'request' => true,
        'unknown' => false,
        'variables' => [],
    ];
    $sink = [
        'kind' => 'sink',
        'file' => $file,
        'scope' => 'example',
        'offset' => 20,
        'line' => 42,
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['user'],
    ];
    $errors = $this->processFindingsAtMinimumProbability(0, [$assignment, $sink]);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe89')
        ->and($errors[0]->getMessage())->toBe(
            'CWE-89: Request input is used in Laravel raw SQL. Use a bound parameter. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html',
        );
});

it('reports an unknown source with a lower confidence and warning', function (): void {
    $event = [
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-89/laravel.php',
        'scope' => 'example',
        'offset' => 20,
        'line' => 43,
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['unresolvedParameter'],
    ];
    $errors = $this->processFindingsAtMinimumProbability(45, [$event]);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe89')
        ->and($errors[0]->getMessage())->toBe(
            'CWE-89: Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter. Severity: high. Probability: 45%. https://cwe.mitre.org/data/definitions/89.html',
        );
});

it('recognizes the Laravel DB global alias without a use statement', function (): void {
    $scope = $this->createMock(Scope::class);
    $scope->method('resolveName')->willReturn('App\\DB');
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    $call = new StaticCall(
        new Name('DB'),
        new Identifier('select'),
        [new Arg(new String_('SELECT * FROM users'))],
    );
    $event = (new Cwe89LaravelCollector())->processNode($call, $scope);

    expect($event)->toBeArray()
        ->and($event['kind'])->toBe('sink')
        ->and($event['file'])->toBe('/tmp/laravel.php');
});

it('checks each supported database facade query method', function (): void {
    $scope = $this->createMock(Scope::class);
    $scope->method('resolveName')->willReturn('Illuminate\\Support\\Facades\\DB');
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    $collector = new Cwe89LaravelCollector();

    foreach (['select', 'insert', 'update', 'delete'] as $method) {
        $event = $collector->processNode(
            new StaticCall(
                new Name\FullyQualified('Illuminate\\Support\\Facades\\DB'),
                new Identifier($method),
                [new Arg(new String_('SQL'))],
            ),
            $scope,
        );

        expect($event)->toBeArray()
            ->and($event['kind'])->toBe('sink');
    }
});

it('rejects a probability minimum outside the valid range', function (): void {
    expect(fn () => new Cwe89LaravelRule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Cwe89LaravelRule(-1))->toThrow(InvalidArgumentException::class);
});

it('filters reports below the configured probability minimum', function (): void {
    $event = [
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-89/laravel.php',
        'scope' => 'example',
        'offset' => 20,
        'line' => 43,
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['unresolvedParameter'],
    ];

    expect($this->processFindingsAtMinimumProbability(46, [$event]))->toBe([])
        ->and($this->processFindingsAtMinimumProbability(45, [$event]))->toHaveCount(1);
});
