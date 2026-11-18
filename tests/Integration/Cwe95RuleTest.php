<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95Collector;
use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95Rule;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe95RuleTestCase extends RuleTestCase
{
    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe95Rule($this->minimumProbability);
    }

    /**
     * @param list<array<string, mixed>|null> $events
     * @param list<array<string, mixed>|null> $ignoreEvents
     * @return list<PHPStan\Rules\IdentifierRuleError>
     */
    public function processEvents(
        array $events,
        array $ignoreEvents = [],
        int $minimumProbability = 0,
    ): array {
        $this->minimumProbability = $minimumProbability;
        $file = __DIR__ . '/../fixtures/CWE-95/cwe95.php';
        $data = [
            $file => [
                Cwe95Collector::class => $events,
                CweIgnoreCollector::class => array_map(
                    static fn (?array $event): ?array => $event === null ? null : [$event],
                    $ignoreEvents,
                ),
            ],
        ];

        return $this->getRule()->processNode(
            new CollectedDataNode($data, false),
            $this->createStub(Scope::class),
        );
    }
}

uses(Cwe95RuleTestCase::class);

covers(Cwe95Rule::class, CweFingerprint::class, Cwe95Collector::class, CweIgnoreCollector::class);

/** @param list<string> $sources */
function cwe95Fingerprint(string $file, string $scope, string $expression, array $sources): string
{
    sort($sources);

    return CweFingerprint::make(95, [$file, $scope, $expression, implode('|', $sources)]);
}

it('records lexical scope bounds without a line-based identity', function (bool $isArrow): void {
    $expression = new PhpParser\Node\Expr\Eval_(new PhpParser\Node\Expr\Variable('code'));
    $attributes = ['startTokenPos' => 10, 'endTokenPos' => 30, 'startLine' => 7];
    $node = $isArrow
        ? new PhpParser\Node\Expr\ArrowFunction(['expr' => $expression], $attributes)
        : new PhpParser\Node\Expr\Closure([], $attributes);
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/closures.php');
    $collector = new Cwe95Collector($this->createStub(PHPStan\Reflection\ReflectionProvider::class));

    expect($collector->processNode($node, $scope))->toBe([
        'kind' => 'scope',
        'file' => '/tmp/closures.php',
        'scope' => '::file',
        'offset' => 10,
        'endOffset' => 30,
    ]);

    $assignment = new PhpParser\Node\Expr\Assign(
        new PhpParser\Node\Expr\Variable('callback'),
        $node,
        ['startTokenPos' => 5, 'endTokenPos' => 30],
    );
    $event = $collector->processNode($assignment, $scope);
    expect($event['sources'])->toBe([])
        ->and($event['variables'])->toBe([])
        ->and($event['unknown'])->toBeTrue()
        ->and($event['startOffset'])->toBe(5);
})->with([false, true]);

it('keeps nested closure flow separate regardless of collected event order', function (): void {
    $events = [
        cwe95Event(['kind' => 'scope', 'offset' => 0, 'endOffset' => 50]),
        cwe95Event(['kind' => 'scope', 'offset' => 15, 'endOffset' => 30]),
        cwe95Event(['kind' => 'assignment', 'offset' => 10, 'startOffset' => 5, 'variable' => 'code', 'sources' => ['php:$_GET["code"]']]),
        cwe95Event(['offset' => 20, 'variables' => ['code']]),
        cwe95Event(['offset' => 40, 'variables' => ['code']]),
        cwe95Event(['offset' => 60, 'variables' => ['code']]),
        null,
    ];
    $errors = $this->processEvents($events);
    $reversed = $this->processEvents(array_reverse($events));

    expect(array_map(static fn ($error): int => $error->getMetadata()['probability'], $errors))
        ->toBe([60, 90, 60])
        ->and(array_map(static fn ($error): string => $error->getMessage(), $reversed))
        ->toBe(array_map(static fn ($error): string => $error->getMessage(), $errors));
});

it('reports direct, assigned, unknown, and fixed eval values with separate ratings', function (): void {
    $events = [
        cwe95Event(['kind' => 'sink', 'line' => 4, 'expression' => 'eval($_GET["code"])', 'sources' => ['php:$_GET["code"]']]),
        cwe95Event(['kind' => 'assignment', 'offset' => 10, 'variable' => 'assignedCode', 'sources' => ['php:$_POST["code"]']]),
        cwe95Event(['kind' => 'sink', 'offset' => 20, 'line' => 6, 'expression' => 'eval($assignedCode)', 'variables' => ['assignedCode']]),
        cwe95Event(['kind' => 'sink', 'offset' => 30, 'line' => 7, 'expression' => 'eval($unknownCode)', 'variables' => ['unknownCode']]),
        cwe95Event(['kind' => 'sink', 'offset' => 40, 'line' => 8, 'expression' => "eval('return 1;')"]),
    ];

    $errors = $this->processEvents($events);

    expect(array_map(static fn ($error): int => $error->getMetadata()['probability'], $errors))
        ->toBe([95, 90, 60, 30])
        ->and(array_map(static fn ($error): string => $error->getMetadata()['severity'], $errors))
        ->toBe(['high', 'high', 'medium', 'low'])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))
        ->toBe([4, 6, 7, 8])
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe95')
        ->and($errors[0]->getMessage())->toContain(
            'CWE-95:',
            'Severity: high.',
            'Probability: 95%.',
            'Fingerprint: ',
            'https://cwe.mitre.org/data/definitions/95.html',
        )
        ->and($errors[0]->getMetadata()['cwe'])->toBe(95)
        ->and($errors[0]->getMetadata()['url'])->toBe('https://cwe.mitre.org/data/definitions/95.html')
        ->and($errors[0]->getMetadata()['fingerprint'])->toMatch('/^[a-f0-9]{64}$/');

    foreach ($errors as $error) {
        expect($error->getTip())->toBe(sprintf(
            'Only ignore this finding if you have checked that the evaluated code is safe. Give a reason with at least two words: // @phpstan-ignore phpstanCwe.cwe95.%s (<reason>)',
            $error->getMetadata()['fingerprint'],
        ));
    }
});

it('requires a reason for a matching fingerprint without suppressing the finding', function (string $annotation): void {
    $event = cwe95Event();
    $fingerprint = cwe95Fingerprint($event['file'], $event['scope'], $event['expression'], []);
    $statement = new PhpParser\Node\Stmt\Expression(
        new PhpParser\Node\Expr\Eval_(new PhpParser\Node\Expr\Variable('code')),
        [
            'comments' => [new PhpParser\Comment(sprintf($annotation, $fingerprint), 3)],
            'startTokenPos' => 20,
            'endTokenPos' => 25,
        ],
    );
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn($event['file']);
    $ignore = (new CweIgnoreCollector())->processNode($statement, $scope);
    $errors = $this->processEvents([$event], $ignore);

    expect(array_map(static fn ($error): string => $error->getIdentifier(), $errors))
        ->toBe(['phpstanCwe.cwe95', 'phpstanCwe.ignoreReason'])
        ->and($errors[1]->getMessage())->toBe('CWE-95 ignore requires a reason with at least two words.')
        ->and($errors[1]->getLine())->toBe(3);
})->with([
    'block comment without reason' => '/* @phpstan-ignore phpstanCwe.cwe95.%s */',
    'line comment without reason' => '// @phpstan-ignore phpstanCwe.cwe95.%s',
    'empty reason' => '// @phpstan-ignore phpstanCwe.cwe95.%s ()',
    'blank reason' => '// @phpstan-ignore phpstanCwe.cwe95.%s (   )',
    'one-word reason' => '// @phpstan-ignore phpstanCwe.cwe95.%s (safe)',
]);

it('suppresses only a matching fingerprint with a valid reason', function (): void {
    $event = cwe95Event(['kind' => 'sink', 'line' => 4, 'expression' => "eval('return 1;')"]);
    $fingerprint = cwe95Fingerprint(
        $event['file'],
        $event['scope'],
        $event['expression'],
        [],
    );
    $ignore = ['cwe' => 95, 'startLine' => 3, 'endLine' => 5, 'file' => $event['file'], 'line' => 3, 'startOffset' => 20, 'endOffset' => 25, 'fingerprint' => $fingerprint, 'reason' => 'Fixed local code'];

    expect($this->processEvents([$event], [$ignore]))->toBe([]);
});

it('reports stale and invalid fingerprint ignores', function (): void {
    $event = cwe95Event(['kind' => 'sink', 'line' => 4, 'expression' => "eval('return 1;')"]);
    $matchingFingerprint = cwe95Fingerprint(
        $event['file'],
        $event['scope'],
        $event['expression'],
        [],
    );
    $ignores = [
        ['cwe' => 95, 'startLine' => 3, 'endLine' => 5, 'file' => $event['file'], 'line' => 3, 'startOffset' => 20, 'endOffset' => 25, 'fingerprint' => str_repeat('0', 64), 'reason' => 'Old safe code'],
        ['cwe' => 95, 'startLine' => 3, 'endLine' => 5, 'file' => $event['file'], 'line' => 5, 'startOffset' => 20, 'endOffset' => 25, 'fingerprint' => 'invalid', 'reason' => 'No longer safe'],
        ['cwe' => 95, 'startLine' => 3, 'endLine' => 5, 'file' => $event['file'], 'line' => 6, 'startOffset' => 20, 'endOffset' => 25, 'fingerprint' => $matchingFingerprint, 'reason' => 'safe'],
    ];

    $errors = $this->processEvents([$event], $ignores);

    expect(array_map(static fn ($error): string => $error->getIdentifier(), $errors))
        ->toBe([
            'phpstanCwe.cwe95',
            'phpstanCwe.ignoreUnmatched',
            'phpstanCwe.ignoreFingerprint',
            'phpstanCwe.ignoreReason',
        ])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))
        ->toBe([4, 3, 5, 6]);
});

it('binds each ignore to one finding in its statement', function (int $ignoreStart, int $ignoreEnd, array $expectedLines): void {
    $first = cwe95Event();
    $second = cwe95Event(['offset' => 30, 'line' => 6]);
    $fingerprint = cwe95Fingerprint($first['file'], $first['scope'], $first['expression'], []);
    $ignore = [
        'cwe' => 95,
        'startLine' => 5,
        'endLine' => 7,
        'file' => $first['file'],
        'line' => 5,
        'startOffset' => $ignoreStart,
        'endOffset' => $ignoreEnd,
        'fingerprint' => $fingerprint,
        'reason' => 'Reviewed local code',
    ];

    $errors = $this->processEvents([$first, $second], [$ignore]);

    expect(array_map(static fn ($error): int => $error->getLine(), $errors))->toBe($expectedLines);
})->with([
    'second statement only' => [30, 35, [4]],
    'one finding per ignore' => [20, 35, [6]],
    'no finding in target statement' => [40, 45, [4, 6, 5]],
]);

it('keeps fingerprints stable for the same sources and changes them when sources change', function (): void {
    $first = cwe95Fingerprint('/tmp/file.php', 'Example::run', 'eval($code)', ['php:$_GET["code"]']);
    $same = cwe95Fingerprint('/tmp/file.php', 'Example::run', 'eval($code)', ['php:$_GET["code"]']);
    $different = cwe95Fingerprint('/tmp/file.php', 'Example::run', 'eval($code)', ['php:$_POST["code"]']);

    expect($first)->toBe($same)
        ->and($first)->not->toBe($different)
        ->and($first)->toMatch('/^[a-f0-9]{64}$/');
});

it('filters findings and rejects an invalid probability minimum', function (): void {
    $directInput = cwe95Event(['sources' => ['php:$_GET["code"]']]);

    expect(invade(new Cwe95Rule())->minProbability)->toBe(0)
        ->and($this->processEvents([$directInput], minimumProbability: 95))->toHaveCount(1)
        ->and($this->processEvents([$directInput], minimumProbability: 96))->toBe([])
        ->and(fn () => new Cwe95Rule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Cwe95Rule(-1))->toThrow(InvalidArgumentException::class);
});

it('uses all fingerprint inputs and sorts source names', function (): void {
    $sources = ['php:$_POST["code"]', 'php:$_GET["code"]'];
    $expected = hash('sha256', "phpstanCwe.cwe95\0/tmp/code.php\0Example::run\0eval(\$code)\0php:\$_GET[\"code\"]|php:\$_POST[\"code\"]");

    expect(cwe95Fingerprint('/tmp/code.php', 'Example::run', 'eval($code)', $sources))->toBe($expected)
        ->and(cwe95Fingerprint('/tmp/code.php', 'Example::run', 'eval($code)', array_reverse($sources)))->toBe($expected);
});

it('gives lexical closures exact source-order identities and excludes their boundaries', function (): void {
    $events = [
        cwe95Event(['kind' => 'scope', 'offset' => 10, 'endOffset' => 40]),
        cwe95Event(['kind' => 'scope', 'offset' => 20, 'endOffset' => 30]),
        cwe95Event(['offset' => 10]),
        cwe95Event(['offset' => 15]),
        cwe95Event(['offset' => 25]),
        cwe95Event(['offset' => 40]),
    ];
    $flow = invade(new Cwe95Rule())->isolateClosureScopes($events);

    expect(array_column($flow, 'scope'))->toBe([
        'Example::evaluate',
        'Example::evaluate::closure1',
        'Example::evaluate::closure2',
        'Example::evaluate',
    ]);
});

it('resolves source facts with exact dependency and assignment states', function (
    array $event,
    array $variables,
    bool $isAssignment,
    array $expected,
): void {
    expect(invade(new Cwe95Rule())->resolveFacts(cwe95Event($event), $variables, $isAssignment))->toBe($expected);
})->with([
    'direct sink' => [['sources' => ['request']], [], false, ['sources' => ['request'], 'unknown' => false, 'throughAssignment' => false]],
    'direct assignment' => [['sources' => ['request']], [], true, ['sources' => ['request'], 'unknown' => false, 'throughAssignment' => true]],
    'fixed assignment' => [[], [], true, ['sources' => [], 'unknown' => false, 'throughAssignment' => false]],
    'missing then present' => [
        ['variables' => ['missing', 'code']],
        ['code' => ['sources' => ['request'], 'unknown' => false, 'throughAssignment' => false]],
        false,
        ['sources' => ['request'], 'unknown' => true, 'throughAssignment' => true],
    ],
    'duplicate sources' => [
        ['sources' => ['first'], 'variables' => ['code']],
        ['code' => ['sources' => ['first', 'second'], 'unknown' => false, 'throughAssignment' => false]],
        false,
        ['sources' => ['first', 'second'], 'unknown' => false, 'throughAssignment' => true],
    ],
    'local unknown' => [
        ['variables' => ['code']],
        ['code' => ['sources' => [], 'unknown' => true, 'throughAssignment' => false]],
        false,
        ['sources' => [], 'unknown' => true, 'throughAssignment' => false],
    ],
    'sink unknown' => [
        ['unknown' => true, 'variables' => ['code']],
        ['code' => ['sources' => [], 'unknown' => false, 'throughAssignment' => false]],
        false,
        ['sources' => [], 'unknown' => true, 'throughAssignment' => false],
    ],
    'prior assignment flag' => [
        ['variables' => ['code']],
        ['code' => ['sources' => [], 'unknown' => false, 'throughAssignment' => true]],
        false,
        ['sources' => [], 'unknown' => false, 'throughAssignment' => true],
    ],
]);

it('keeps direct input rating when a sink also has an assigned input', function (): void {
    $errors = $this->processEvents([
        cwe95Event(['kind' => 'assignment', 'offset' => 10, 'variable' => 'code', 'sources' => ['first']]),
        cwe95Event(['sources' => ['second'], 'variables' => ['code']]),
    ]);
    expect($errors[0]->getMetadata()['probability'])->toBe(95);
});

it('matches two-word reasons and consumes each ignore once before continuing reports', function (): void {
    $first = cwe95Event();
    $second = cwe95Event(['offset' => 40, 'line' => 8]);
    $fingerprint = cwe95Fingerprint($first['file'], $first['scope'], $first['expression'], []);
    $ignore = [
        'cwe' => 95,
        'startLine' => 5,
        'endLine' => 7,
        'file' => $first['file'], 'line' => 3, 'startOffset' => 10, 'endOffset' => 20,
        'fingerprint' => $fingerprint, 'reason' => 'Reviewed code',
    ];
    $staleIgnore = array_replace($ignore, ['line' => 6, 'startOffset' => 30, 'endOffset' => 35]);

    $errors = $this->processEvents([$first, $second], [null, $ignore, $staleIgnore]);
    expect(array_map(static fn ($error): string => $error->getIdentifier(), $errors))
        ->toBe(['phpstanCwe.cwe95', 'phpstanCwe.ignoreUnmatched'])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))->toBe([8, 6]);
});

it('continues past files whose ignore data has already been processed', function (): void {
    $firstFile = __DIR__ . '/../fixtures/CWE-95/cwe95.php';
    $secondFile = __DIR__ . '/../fixtures/CWE-95/stale-ignore.php';
    $ignore = [
        'cwe' => 95, 'startLine' => 3, 'endLine' => 5,
        'file' => $secondFile, 'line' => 3, 'startOffset' => 10, 'endOffset' => 20,
        'fingerprint' => str_repeat('a', 64), 'reason' => 'Reviewed code',
    ];
    $node = new CollectedDataNode([
        $firstFile => [Cwe95Collector::class => [null], CweIgnoreCollector::class => [null]],
        $secondFile => [CweIgnoreCollector::class => [[$ignore]]],
    ], false);
    $errors = (new Cwe95Rule())->processNode($node, $this->createStub(Scope::class));

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getFile())->toBe($secondFile);
});

it('continues past low probability findings to report later input', function (): void {
    $errors = $this->processEvents([
        cwe95Event(['offset' => 10]),
        cwe95Event(['offset' => 20, 'sources' => ['request']]),
    ], minimumProbability: 95);

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getMetadata()['probability'])->toBe(95);
});

it('reports stale ignores when a file has no collected eval events', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-95/stale-ignore.php';
    $ignore = [
        'cwe' => 95,
        'startLine' => 3,
        'endLine' => 5,
        'file' => $file,
        'line' => 3,
        'startOffset' => 20,
        'endOffset' => 25,
        'fingerprint' => str_repeat('a', 64),
        'reason' => 'Reviewed local code',
    ];
    $rule = new Cwe95Rule();
    $node = new CollectedDataNode([
        $file => [CweIgnoreCollector::class => [null, [$ignore]]],
    ], false);
    $errors = $rule->processNode($node, $this->createStub(Scope::class));

    expect($rule->getNodeType())->toBe(CollectedDataNode::class)
        ->and($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.ignoreUnmatched')
        ->and($errors[0]->getFile())->toBe($file)
        ->and($errors[0]->getLine())->toBe(3)
        ->and($errors[0]->getMessage())->toBe('CWE-95 ignore fingerprint does not match a finding. Review or remove this ignore.');
});

function cwe95Event(array $changes = []): array
{
    return array_replace([
        'kind' => 'sink',
        'file' => __DIR__ . '/../fixtures/CWE-95/cwe95.php',
        'scope' => 'Example::evaluate',
        'offset' => 20,
        'startOffset' => 20,
        'line' => 4,
        'expression' => 'eval($code)',
        'sources' => [],
        'unknown' => false,
        'variables' => [],
    ], $changes);
}
