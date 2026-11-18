<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Rule;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe78RuleTestCase extends RuleTestCase
{
    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe78Rule($this->minimumProbability);
    }

    /**
     * @param list<array<string, mixed>|null> $events
     * @return list<PHPStan\Rules\IdentifierRuleError>
     */
    public function processEvents(array $events, int $minimumProbability = 0): array
    {
        $this->minimumProbability = $minimumProbability;
        $file = __DIR__ . '/../fixtures/CWE-78/cwe78.php';
        $data = [
            $file => [
                Cwe78Collector::class => $events,
            ],
        ];

        return $this->getRule()->processNode(
            new CollectedDataNode($data, false),
            $this->createStub(Scope::class),
        );
    }
}

uses(Cwe78RuleTestCase::class);

covers(Cwe78Rule::class);

it('reports direct input with the highest rating and complete report metadata', function (): void {
    $errors = $this->processEvents([cwe78Sink(['request' => true])]);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe78')
        ->and(withoutFingerprint($errors[0]->getMessage()))->toBe(
            'CWE-78: Request input is used as the full command. Use a fixed executable and safe arguments. Severity: very high. Probability: 95%. https://cwe.mitre.org/data/definitions/78.html',
        )
        ->and(array_diff_key($errors[0]->getMetadata(), ['fingerprint' => true]))->toBe([
            'cwe' => 78,
            'severity' => 'very high',
            'probability' => 95,
            'url' => 'https://cwe.mitre.org/data/definitions/78.html',
        ])
        ->and($errors[0]->getMetadata()['fingerprint'])->toMatch('/^[a-f0-9]{64}$/')
        ->and($errors[0]->getLine())->toBe(4);
});

it('reports lower ratings for known command text, assigned values, and untraced sinks', function (): void {
    $assignment = cwe78Sink([
        'kind' => 'assignment',
        'offset' => 10,
        'variable' => 'command',
        'request' => true,
        'hasStaticText' => false,
        'variables' => [],
    ]);
    unset($assignment['line'], $assignment['throughAssignment']);
    $events = [
        cwe78Sink(['offset' => 20, 'request' => true, 'hasStaticText' => true]),
        $assignment,
        cwe78Sink(['offset' => 30, 'variables' => ['command'], 'throughAssignment' => true]),
        cwe78Sink([
            'kind' => 'assignment',
            'offset' => 35,
            'variable' => 'staticCommand',
            'request' => false,
            'hasStaticText' => true,
        ]),
        cwe78Sink(['offset' => 36, 'request' => true, 'variables' => ['staticCommand']]),
        cwe78Sink(['offset' => 40, 'request' => false, 'variables' => ['unresolved']]),
    ];
    unset($events[3]['line'], $events[3]['throughAssignment']);
    $errors = $this->processEvents($events);

    expect(array_map(static fn ($error): int => $error->getMetadata()['probability'], $errors))
        ->toBe([80, 60, 80, 50])
        ->and(array_map(static fn ($error): string => $error->getMetadata()['severity'], $errors))
        ->toBe(['high', 'medium', 'high', 'low'])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))
        ->toBe([4, 4, 4, 4]);
});

it('sorts events, skips missing sources, and keeps request tracking scoped to assignments', function (): void {
    $assignment = cwe78Sink([
        'kind' => 'assignment',
        'offset' => 10,
        'variable' => 'requestCommand',
        'request' => true,
        'hasStaticText' => false,
        'variables' => [],
    ]);
    unset($assignment['line'], $assignment['throughAssignment']);
    $events = [
        cwe78Sink(['offset' => 30, 'variables' => ['missing', 'requestCommand']]),
        null,
        $assignment,
    ];
    $errors = $this->processEvents($events);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getMetadata()['probability'])->toBe(60)
        ->and($errors[0]->getMetadata()['severity'])->toBe('medium');
});

it('continues after a filtered finding', function (): void {
    $events = [
        cwe78Sink(['offset' => 10, 'request' => true, 'hasStaticText' => true]),
        cwe78Sink(['offset' => 20, 'request' => true]),
    ];
    $errors = $this->processEvents($events, 90);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getMetadata()['probability'])->toBe(95)
        ->and($errors[0]->getLine())->toBe(4);
});

it('uses CollectedDataNode for package rule processing', function (): void {
    expect($this->getRule()->getNodeType())->toBe(CollectedDataNode::class);
});

it('uses zero as the default probability minimum', function (): void {
    expect(invade(new Cwe78Rule())->minProbability)->toBe(0);
});

it('filters findings below the configured minimum and validates its range', function (): void {
    expect($this->processEvents([cwe78Sink(['request' => true])], minimumProbability: 96))->toBe([])
        ->and(fn () => new Cwe78Rule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Cwe78Rule(-1))->toThrow(InvalidArgumentException::class);
});

function cwe78Sink(array $changes = []): array
{
    return array_replace([
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-78/cwe78.php',
        'scope' => 'Example::command',
        'expression' => 'shell_exec($command)',
        'offset' => 20,
        'line' => 4,
        'request' => false,
        'hasStaticText' => false,
        'throughAssignment' => false,
        'variables' => [],
    ], $changes);
}
