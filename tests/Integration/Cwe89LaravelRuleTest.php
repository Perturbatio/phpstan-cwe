<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelRule;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelCollector;
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
            if ($event === null) {
                $collectedData[__DIR__ . '/../fixtures/CWE-89/laravel.php'][Cwe89LaravelCollector::class][] = null;
                continue;
            }
            $collectedData[$event['file']][Cwe89LaravelCollector::class][] = $event;
        }
        $node = new CollectedDataNode($collectedData, false);

        return $this->getRule()->processNode($node, $this->createStub(Scope::class));
    }
}

uses(Cwe89LaravelRuleTestCase::class);

covers(Cwe89LaravelRule::class, Cwe89LaravelCollector::class);

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
        )
        ->and($errors[0]->getTip())->toBe(
            'If you use wrap() for an SQL identifier, verify that PHPStan knows the argument is a string and the receiver is Illuminate\Database\Grammar or a subclass. Add or correct parameter types where needed. A string type alone does not make raw SQL safe. Use bound parameters for values.',
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
        )
        ->and($errors[0]->getTip())->toBe(
            'If you use wrap() for an SQL identifier, verify that PHPStan knows the argument is a string and the receiver is Illuminate\Database\Grammar or a subclass. Add or correct parameter types where needed. A string type alone does not make raw SQL safe. Use bound parameters for values.',
        );
});

it('does not report a static Laravel raw SQL expression', function (): void {
    $event = [
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-89/laravel.php',
        'scope' => 'example',
        'offset' => 20,
        'line' => 43,
        'dynamic' => false,
        'request' => false,
        'unknown' => false,
        'variables' => [],
    ];

    expect($this->processFindingsAtMinimumProbability(0, [$event]))->toBe([]);
});

it('recognizes the Laravel DB global alias without a use statement', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('resolveName')->willReturn('App\\DB');
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    $call = new StaticCall(
        new Name('DB'),
        new Identifier('select'),
        [new Arg(new String_('SELECT * FROM users'))],
    );
    $event = (new Cwe89LaravelCollector($this->getContainer()->getByType(PHPStan\Reflection\ReflectionProvider::class)))->processNode($call, $scope);

    expect($event)->toBeArray()
        ->and($event['kind'])->toBe('sink')
        ->and($event['file'])->toBe('/tmp/laravel.php');
});

it('checks each supported database facade query method', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('resolveName')->willReturn('Illuminate\\Support\\Facades\\DB');
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    $collector = new Cwe89LaravelCollector($this->getContainer()->getByType(PHPStan\Reflection\ReflectionProvider::class));

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

it('returns the correct node type for the rule', function (): void {
    expect($this->getRule()->getNodeType())->toBe(CollectedDataNode::class);
});

it('uses the expected default probabilities', function (): void {
    expect(Cwe89LaravelRule::getRequestProbability())->toBe(80)
        ->and(Cwe89LaravelRule::getUnknownProbability())->toBe(45);
});

function laravelSqlSink(array $changes = []): array
{
    return array_replace([
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-89/laravel.php',
        'scope' => 'Example::query',
        'offset' => 20,
        'line' => 4,
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => [],
    ], $changes);
}

it('uses zero as the default minimum probability', function (): void {
    expect(invade(new Cwe89LaravelRule())->minProbability)->toBe(0);
});

it('sorts events and isolates assignments by file and callable', function (): void {
    $assignment = laravelSqlSink([
        'kind' => 'assignment',
        'offset' => 10,
        'variable' => 'query',
        'request' => true,
    ]);
    unset($assignment['line']);
    $events = [
        laravelSqlSink(['variables' => ['query']]),
        null,
        $assignment,
        laravelSqlSink(['scope' => 'Other::query', 'variables' => ['query'], 'line' => 5]),
        laravelSqlSink(['file' => __DIR__ . '/../fixtures/CWE-89/cwe89.php', 'variables' => ['query'], 'line' => 6]),
    ];
    $errors = $this->processFindingsAtMinimumProbability(0, $events);

    expect($errors)->toHaveCount(3)
        ->and($errors[0]->getMetadata())->toBe([
            'cwe' => 89, 'severity' => 'high', 'probability' => 80, 'url' => 'https://cwe.mitre.org/data/definitions/89.html',
        ])
        ->and($errors[0]->getLine())->toBe(4)
        ->and($errors[0]->getFile())->toBe(__DIR__ . '/../fixtures/CWE-89/laravel.php')
        ->and($errors[1]->getMetadata()['probability'])->toBe(45)
        ->and($errors[2]->getMetadata()['probability'])->toBe(45)
        ->and($errors[2]->getFile())->toBe(__DIR__ . '/../fixtures/CWE-89/cwe89.php');
});

it('continues after static and filtered sinks', function (): void {
    $events = [
        laravelSqlSink(['offset' => 10, 'dynamic' => false]),
        laravelSqlSink(['offset' => 20, 'unknown' => true]),
        laravelSqlSink(['offset' => 30, 'request' => true, 'line' => 8]),
    ];
    $errors = $this->processFindingsAtMinimumProbability(80, $events);
    expect($errors)->toHaveCount(1)->and($errors[0]->getLine())->toBe(8);
});

it('keeps known request input distinct from unknown and static values', function (): void {
    $assignment = laravelSqlSink(['kind' => 'assignment', 'variable' => 'safe', 'dynamic' => false, 'offset' => 1]);
    unset($assignment['line']);
    $events = [
        $assignment,
        laravelSqlSink(['offset' => 10, 'variables' => ['safe'], 'line' => 1]),
        laravelSqlSink(['offset' => 20, 'unknown' => true, 'line' => 2]),
        laravelSqlSink(['offset' => 30, 'request' => true, 'unknown' => true, 'line' => 3]),
        laravelSqlSink(['offset' => 40, 'request' => true, 'variables' => ['unknown'], 'line' => 4]),
    ];
    $errors = $this->processFindingsAtMinimumProbability(0, $events);
    expect($errors)->toHaveCount(3)
        ->and(array_map(static fn ($error): int => $error->getMetadata()['probability'], $errors))->toBe([45, 80, 80])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))->toBe([2, 3, 4]);
});
