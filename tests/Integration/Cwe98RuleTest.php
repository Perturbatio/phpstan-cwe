<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\RequestInput;
use Perturbatio\PhpstanCwe\Rules\Cwe98\Cwe98Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe98\Cwe98Rule;
use PhpParser\Node;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\FileRuleError;
use PHPStan\Rules\LineRuleError;
use PHPStan\Rules\MetadataRuleError;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PHPStan\Type\MixedType;

class Cwe98RuleTestCase extends RuleTestCase
{
    use AnalysesWithoutFingerprints;

    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return new Cwe98Rule($this->minimumProbability);
    }

    protected function getCollectors(): array
    {
        return [
            $this->makeCollector(),
            new CweIgnoreCollector(),
        ];
    }

    public function makeRule(int $minimumProbability = 0): Cwe98Rule
    {
        return new Cwe98Rule($minimumProbability);
    }

    public function makeCollector(): Cwe98Collector
    {
        return new Cwe98Collector($this->getContainer()->getByType(ReflectionProvider::class));
    }

    /**
     * @param list<array{0: string, 1: int, 2?: string}> $expectedErrors
     */
    public function checkFixture(array $expectedErrors): void
    {
        $this->analyse([__DIR__ . '/../fixtures/CWE-98/cwe98.php'], $expectedErrors);
    }

    /**
     * @param list<array{0: string, 1: int, 2?: string}> $expectedErrors
     */
    public function checkFixtureAtMinimumProbability(int $minimumProbability, array $expectedErrors): void
    {
        $this->minimumProbability = $minimumProbability;
        $this->checkFixture($expectedErrors);
    }

    /**
     * @param list<array<string, mixed>|null> $events
     * @param list<array<string, mixed>|null> $ignoreEvents
     * @return list<PHPStan\Rules\IdentifierRuleError>
     */
    public function processEvents(array $events, array $ignoreEvents = [], int $minimumProbability = 0): array
    {
        $file = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
        $data = [
            $file => [
                Cwe98Collector::class => $events,
                CweIgnoreCollector::class => array_map(
                    static fn (?array $event): ?array => $event === null ? null : [$event],
                    $ignoreEvents,
                ),
            ],
        ];

        return (new Cwe98Rule($minimumProbability))->processNode(
            new CollectedDataNode($data, false),
            $this->createStub(Scope::class),
        );
    }

    public function collect(Node $node, ?Scope $scope = null): ?array
    {
        return $this->makeCollector()->processNode($node, $scope ?? $this->createStub(Scope::class));
    }
}

uses(Cwe98RuleTestCase::class);

covers(Cwe98Rule::class, Cwe98Collector::class, RequestInput::class);

/**
 * @param list<array{0: int, 1: int}> $reports
 * @return list<array{0: string, 1: int}>
 */
function cwe98ExpectedReports(array $reports): array
{
    return array_map(
        static fn (array $report): array => [
            sprintf(
                'CWE-98: %s Severity: high. Probability: %d%%. https://cwe.mitre.org/data/definitions/98.html',
                $report[0] === 60
                    ? 'The include filename is dynamic and its source is unknown. Use a fixed allow-list.'
                    : 'Request input is used in an include filename. Select files from a fixed allow-list.',
                $report[0],
            ),
            $report[1],
        ],
        $reports,
    );
}

it('does not collect index variables from nested request input', function (
    string $expression,
    bool $hasInput,
    array $expectedVariables,
): void {
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php ' . $expression . ';');
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new MixedType());
    $variables = [];

    expect(RequestInput::inInclude(
        $nodes[0]->expr,
        $scope,
        $this->getContainer()->getByType(ReflectionProvider::class),
        static function (string $variable) use (&$variables): bool {
            $variables[] = $variable;

            return false;
        },
    ))->toBe($hasInput)
        ->and($variables)->toBe($expectedVariables);
})->with([
    'nested request input' => ['$_GET["pages"][$index]', true, []],
    'nested local array' => ['$pages["paths"][$index]', false, ['pages', 'index']],
]);

it('reports request input and unknown dynamic include filenames with separate scores', function (): void {
    $this->checkFixture(cwe98ExpectedReports([
        [95, 5],
        [95, 6],
        [95, 11],
        [95, 15],
        [95, 17],
        [95, 18],
        [85, 19],
        [45, 20],
        [95, 26],
        [95, 36],
        [60, 41],
        [60, 42],
        [60, 43],
        [95, 44],
        [95, 45],
        [60, 52],
        [95, 54],
        [60, 56],
        [95, 61],
        [60, 66],
    ]));
});

it('keeps the correct probability through assignments and filename expressions', function (): void {
    $this->analyse([__DIR__ . '/../fixtures/CWE-98/flow.php'], cwe98ExpectedReports([
        [95, 12],
        [85, 13],
        [45, 14],
        [85, 15],
        [45, 16],
        [85, 17],
        [45, 18],
        [45, 19],
        [95, 20],
        [60, 21],
        [95, 22],
        [45, 25],
        [95, 26],
        [60, 28],
    ]));
});

it('filters reports at and above each configured minimum probability', function (int $minimumProbability, array $reports): void {
    $this->checkFixtureAtMinimumProbability($minimumProbability, cwe98ExpectedReports($reports));
})->with([
    'greater than 95 filters all findings' => [96, []],
    '95 includes unchanged input' => [95, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [95, 26], [95, 36], [95, 44], [95, 45], [95, 54], [95, 61]]],
    '86 excludes transformed input' => [86, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [95, 26], [95, 36], [95, 44], [95, 45], [95, 54], [95, 61]]],
    '85 includes transformed input' => [85, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [85, 19], [95, 26], [95, 36], [95, 44], [95, 45], [95, 54], [95, 61]]],
    '61 excludes unknown values' => [61, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [85, 19], [95, 26], [95, 36], [95, 44], [95, 45], [95, 54], [95, 61]]],
    '60 includes unknown values' => [60, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [85, 19], [95, 26], [95, 36], [60, 41], [60, 42], [60, 43], [95, 44], [95, 45], [60, 52], [95, 54], [60, 56], [95, 61], [60, 66]]],
    '46 excludes numeric input' => [46, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [85, 19], [95, 26], [95, 36], [60, 41], [60, 42], [60, 43], [95, 44], [95, 45], [60, 52], [95, 54], [60, 56], [95, 61], [60, 66]]],
    '45 includes numeric input' => [45, [[95, 5], [95, 6], [95, 11], [95, 15], [95, 17], [95, 18], [85, 19], [45, 20], [95, 26], [95, 36], [60, 41], [60, 42], [60, 43], [95, 44], [95, 45], [60, 52], [95, 54], [60, 56], [95, 61], [60, 66]]],
]);

it('loads the single-rule configuration and full extension', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-98/cwe98.php', true);
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(20)
        ->and(array_column($messages, 'identifier'))->toBe(array_fill(0, 20, 'phpstanCwe.cwe98'))
        ->and(array_column($messages, 'line'))->toBe([5, 6, 11, 15, 17, 18, 19, 20, 26, 36, 41, 42, 43, 44, 45, 52, 54, 56, 61, 66])
        ->and(array_column($messages, 'ignorable'))->toBe(array_fill(0, 20, true))
        ->and($messages[0]['message'])->toContain(
            'Severity: high.',
            'Probability: 95%.',
            'Fingerprint: ',
            'https://cwe.mitre.org/data/definitions/98.html',
        );
})->with([
    'config/cwe98.neon',
    'tests/fixtures/CWE-98/extension.neon',
]);

it('reports Laravel include filenames with their source and probability', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-98/laravel.php', true);
    $fixture = realpath(__DIR__ . '/../fixtures/CWE-98/laravel.php');
    $messages = $result['files'][$fixture]['messages'];
    $expectedReports = cwe98ExpectedReports([
        [85, 41],
        [85, 49],
        [95, 54],
        [85, 55],
        [45, 56],
        [85, 72],
    ]);

    expect(array_keys($result['files']))->toBe([$fixture])
        ->and($result['totals']['file_errors'])->toBe(count($expectedReports))
        ->and(array_column($messages, 'identifier'))->toBe(array_fill(0, count($expectedReports), 'phpstanCwe.cwe98'))
        ->and(array_column($messages, 'ignorable'))->toBe(array_fill(0, count($expectedReports), true))
        ->and(array_map(
            static fn (array $message): array => [withoutFingerprint($message['message']), $message['line']],
            $messages,
        ))->toBe($expectedReports);

    foreach ($messages as $message) {
        expect($message['message'])->toMatch('/Fingerprint: [a-f0-9]{64}\./')
            ->and($message['tip'])->toContain('@phpstan-ignore phpstanCwe.cwe98.');
    }
})->with([
    'single rule' => 'config/cwe98.neon',
    'full extension' => 'tests/fixtures/CWE-98/extension.neon',
]);

it('tracks Laravel path helpers, list changes, and route parameters', function (): void {
    $this->analyse([__DIR__ . '/../fixtures/CWE-98/laravel-paths.php'], cwe98ExpectedReports([
        [85, 9],
        [60, 10],
        [60, 12],
        [95, 22],
        [85, 28],
        [95, 32],
        [95, 42],
        [85, 47],
        [60, 49],
        [60, 53],
        [95, 73],
        [60, 79],
        [60, 90],
        [45, 92],
        [60, 101],
        [95, 110],
    ]));
});

it('resolves shadowed path helpers in both configurations', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-98/laravel-paths.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(array_fill(0, 17, 'phpstanCwe.cwe98'))
        ->and(array_map(
            static fn (array $message): array => [$message['message'], $message['line']],
            $messages,
        ))->toBe(cwe98ExpectedReports([
            [85, 9], [60, 10], [60, 12], [60, 13], [95, 22], [85, 28],
            [95, 32], [95, 42], [85, 47], [60, 49], [60, 53], [95, 73], [60, 79],
            [60, 90], [45, 92], [60, 101], [95, 110],
        ]));
})->with([
    'single rule' => 'config/cwe98.neon',
    'full extension' => 'tests/fixtures/CWE-98/extension.neon',
]);

it('keeps fingerprints stable and applies one ignore annotation to one finding', function (): void {
    $temporaryFile = tempnam(sys_get_temp_dir(), 'phpstan-cwe98-');
    if ($temporaryFile === false) {
        throw new RuntimeException('Cannot create a temporary PHP fixture.');
    }
    $file = $temporaryFile . '.php';
    unlink($temporaryFile);

    $analyse = static function (string $code) use ($file): array {
        file_put_contents($file, $code);
        $result = analyseWithConfig('config/cwe98.neon', $file, true);

        return array_values($result['files'])[0]['messages'];
    };

    try {
        $baseline = $analyse("<?php\ninclude \$_GET['page'];\ninclude \$_GET['page'];\n");
        preg_match('/Fingerprint: ([a-f0-9]{64})\\./', $baseline[0]['message'], $matches);
        $fingerprint = $matches[1];
        $shifted = $analyse("<?php\n// This comment does not change the finding.\n\ninclude \$_GET['page'];\ninclude \$_GET['page'];\n");
        preg_match('/Fingerprint: ([a-f0-9]{64})\\./', $shifted[0]['message'], $shiftedMatches);

        $ignored = $analyse(sprintf(
            "<?php\n// @phpstan-ignore phpstanCwe.cwe98.%s (Reviewed path)\ninclude \$_GET['page'];\ninclude \$_GET['page'];\n",
            $fingerprint,
        ));

        expect($baseline)->toHaveCount(2)
            ->and(array_map(static fn (array $message): string => $message['identifier'], $baseline))->toBe([
                'phpstanCwe.cwe98',
                'phpstanCwe.cwe98',
            ])
            ->and($fingerprint)->toBe($shiftedMatches[1])
            ->and(array_column($ignored, 'identifier'))->toBe(['phpstanCwe.cwe98'])
            ->and($ignored[0]['identifier'])->toBe('phpstanCwe.cwe98');
    } finally {
        if (file_exists($file)) {
            unlink($file);
        }
    }
});

it('rejects a minimum probability outside the valid range', function (): void {
    expect(fn () => $this->makeRule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $this->makeRule(-1))->toThrow(InvalidArgumentException::class);
});

it('exposes the report probability defaults', function (): void {
    expect(Cwe98Rule::getUnchangedInputProbability())->toBe(95)
        ->and(Cwe98Rule::getTransformedInputProbability())->toBe(85)
        ->and(Cwe98Rule::getUnknownValueProbability())->toBe(60)
        ->and(Cwe98Rule::getNumericInputProbability())->toBe(45)
        ->and(Cwe98Rule::getLowestProbability())->toBe(45)
        ->and(invade(new Cwe98Rule())->minProbability)->toBe(0)
        ->and($this->makeRule()->getNodeType())->toBe(CollectedDataNode::class);
});

it('resolves all dependencies after an unknown value and keeps the strongest request score', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
    $base = [
        'file' => $file,
        'scope' => '::file',
        'startOffset' => 0,
        'sources' => [],
        'requestProbability' => null,
        'unknown' => false,
        'variables' => [],
    ];
    $events = [
        [...$base, 'kind' => 'assignment', 'offset' => 1, 'variable' => 'raw', 'sources' => ['php:$_POST["page"]'], 'requestProbability' => 95],
        [...$base, 'kind' => 'assignment', 'offset' => 2, 'variable' => 'changed', 'sources' => ['php:$_GET["page"]'], 'requestProbability' => 85],
        [...$base, 'kind' => 'assignment', 'offset' => 3, 'variable' => 'unknown', 'variables' => ['missing' => 95]],
        [...$base, 'kind' => 'sink', 'offset' => 4, 'line' => 4, 'expression' => '$missing . $raw . $changed', 'variables' => ['missing' => 95, 'raw' => 85, 'changed' => 95]],
        [...$base, 'kind' => 'sink', 'offset' => 5, 'line' => 5, 'expression' => '$unknown', 'variables' => ['unknown' => 95]],
        [...$base, 'kind' => 'sink', 'offset' => 6, 'line' => 6, 'expression' => '"fixed"'],
        null,
    ];
    $errors = $this->processEvents($events);
    $fingerprint = CweFingerprint::make(98, [
        $file,
        '::file',
        '$missing . $raw . $changed',
        'php:$_GET["page"]|php:$_POST["page"]',
        '85',
    ]);

    expect($errors)->toHaveCount(2)
        ->and($errors[0]->getLine())->toBe(4)
        ->and($errors[0]->getMetadata()['probability'])->toBe(85)
        ->and($errors[0]->getMetadata()['fingerprint'])->toBe($fingerprint)
        ->and($errors[1]->getLine())->toBe(5)
        ->and($errors[1]->getMetadata()['probability'])->toBe(60);
});

it('resolves filename facts from each assignment dependency', function (array $event, array $variables, array $expected): void {
    $event += ['sources' => [], 'requestProbability' => null, 'unknown' => false, 'variables' => []];

    expect(invade($this->makeRule())->resolveFacts($event, $variables, false))->toBe($expected);
})->with([
    'fixed expression' => [[], [], ['sources' => [], 'requestProbability' => null, 'unknown' => false]],
    'missing dependency' => [['variables' => ['missing' => 95]], [], ['sources' => [], 'requestProbability' => null, 'unknown' => true]],
    'fixed dependency' => [
        ['variables' => ['fixed' => 95]],
        ['fixed' => ['sources' => [], 'requestProbability' => null, 'unknown' => false]],
        ['sources' => [], 'requestProbability' => null, 'unknown' => false],
    ],
    'unknown dependency' => [
        ['variables' => ['unknown' => 95]],
        ['unknown' => ['sources' => [], 'requestProbability' => null, 'unknown' => true]],
        ['sources' => [], 'requestProbability' => null, 'unknown' => true],
    ],
    'unknown expression with known dependency' => [
        ['unknown' => true, 'variables' => ['value' => 95]],
        ['value' => ['sources' => ['request'], 'requestProbability' => 95, 'unknown' => false]],
        ['sources' => ['request'], 'requestProbability' => 95, 'unknown' => true],
    ],
    'numeric modifier lowers dependency score' => [
        ['variables' => ['value' => 45]],
        ['value' => ['sources' => ['request'], 'requestProbability' => 95, 'unknown' => false]],
        ['sources' => ['request'], 'requestProbability' => 45, 'unknown' => false],
    ],
    'dependency score remains below modifier' => [
        ['variables' => ['value' => 95]],
        ['value' => ['sources' => ['request'], 'requestProbability' => 85, 'unknown' => false]],
        ['sources' => ['request'], 'requestProbability' => 85, 'unknown' => false],
    ],
    'direct score is stronger' => [
        ['sources' => ['direct'], 'requestProbability' => 95, 'variables' => ['value' => 85]],
        ['value' => ['sources' => ['assigned'], 'requestProbability' => 95, 'unknown' => false]],
        ['sources' => ['direct', 'assigned'], 'requestProbability' => 95, 'unknown' => false],
    ],
    'dependency score is stronger' => [
        ['sources' => ['direct'], 'requestProbability' => 45, 'variables' => ['value' => 95]],
        ['value' => ['sources' => ['assigned'], 'requestProbability' => 85, 'unknown' => false]],
        ['sources' => ['direct', 'assigned'], 'requestProbability' => 85, 'unknown' => false],
    ],
    'duplicate sources remain unique' => [
        ['sources' => ['first', 'second'], 'requestProbability' => 95, 'variables' => ['value' => 95]],
        ['value' => ['sources' => ['first', 'third'], 'requestProbability' => 95, 'unknown' => false]],
        ['sources' => ['first', 'second', 'third'], 'requestProbability' => 95, 'unknown' => false],
    ],
]);

it('validates matching and stale annotations before filtering each probability', function (int $probability): void {
    $file = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
    $sources = $probability === 60 ? [] : ['php:$_GET["page"]'];
    $event = [
        'kind' => 'sink',
        'file' => $file,
        'scope' => '::file',
        'offset' => 12,
        'startOffset' => 10,
        'line' => 2,
        'expression' => '$page',
        'sources' => $sources,
        'requestProbability' => $probability === 60 ? null : $probability,
        'unknown' => $probability === 60,
        'variables' => [],
    ];
    $fingerprint = CweFingerprint::make(98, [$file, '::file', '$page', implode('|', $sources), (string) $probability]);
    $ignore = [
        'cwe' => 98,
        'file' => $file,
        'line' => 1,
        'startLine' => 1,
        'endLine' => 2,
        'startOffset' => 10,
        'endOffset' => 12,
        'fingerprint' => $fingerprint,
        'reason' => 'Reviewed path',
    ];
    $stale = [...$ignore, 'fingerprint' => str_repeat('0', 64)];
    $invalidReason = [...$ignore, 'reason' => 'Reviewed'];

    expect($this->processEvents([$event], minimumProbability: $probability))->toHaveCount(1)
        ->and($this->processEvents([$event], minimumProbability: $probability + 1))->toBe([])
        ->and($this->processEvents([$event], [$ignore], $probability + 1))->toBe([])
        ->and(array_map(static fn ($error): string => $error->getIdentifier(), $this->processEvents([$event], [$stale], $probability + 1)))
        ->toBe(['phpstanCwe.unmatchedAnnotation'])
        ->and(array_map(static fn ($error): string => $error->getIdentifier(), $this->processEvents([$event], [$invalidReason])))
        ->toBe(['phpstanCwe.cwe98', 'phpstanCwe.ignoreReason']);
})->with([95, 85, 60, 45]);

it('keeps assignment facts separate for each file and named scope', function (): void {
    $base = [
        'scope' => 'Example::first',
        'startOffset' => 0,
        'sources' => [],
        'requestProbability' => null,
        'unknown' => false,
        'variables' => [],
    ];
    $first = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
    $second = __DIR__ . '/../fixtures/CWE-98/flow.php';
    $data = [
        $first => [
            Cwe98Collector::class => [
                [...$base, 'kind' => 'assignment', 'file' => $first, 'offset' => 1, 'variable' => 'page', 'sources' => ['php:$_GET["page"]'], 'requestProbability' => 95],
                [...$base, 'kind' => 'sink', 'file' => $first, 'offset' => 2, 'line' => 2, 'expression' => '$page', 'variables' => ['page' => 95]],
                [...$base, 'kind' => 'sink', 'file' => $first, 'scope' => 'Example::second', 'offset' => 3, 'line' => 3, 'expression' => '$page', 'variables' => ['page' => 95]],
            ],
        ],
        $second => [
            Cwe98Collector::class => [
                [...$base, 'kind' => 'sink', 'file' => $second, 'offset' => 1, 'line' => 1, 'expression' => '$page', 'variables' => ['page' => 95]],
            ],
        ],
    ];
    $errors = $this->makeRule()->processNode(new CollectedDataNode($data, false), $this->createStub(Scope::class));

    expect(array_map(static fn ($error): int => $error->getMetadata()['probability'], $errors))->toBe([95, 60, 60])
        ->and(array_map(static fn ($error): string => $error->getFile(), $errors))->toBe([$first, $first, $second])
        ->and(array_map(static fn ($error): int => $error->getLine(), $errors))->toBe([2, 3, 1]);
});

it('reports an invalid annotation even when its file has no include events', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
    $annotation = [
        'cwe' => 98,
        'file' => $file,
        'line' => 3,
        'startLine' => 3,
        'endLine' => 4,
        'startOffset' => 1,
        'endOffset' => 2,
        'fingerprint' => 'invalid',
        'reason' => 'Reviewed path',
    ];
    $node = new CollectedDataNode([$file => [CweIgnoreCollector::class => [[$annotation]]]], false);
    $errors = $this->makeRule()->processNode($node, $this->createStub(Scope::class));

    expect($errors)->toHaveCount(1)
        ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.annotationFingerprint')
        ->and($errors[0]->getFile())->toBe($file)
        ->and($errors[0]->getLine())->toBe(3);
});

it('adds CWE, severity, score, link, fingerprint, file, and line to a report', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-98/cwe98.php';
    $fingerprint = CweFingerprint::make(98, [
        $file,
        '::file',
        "\$_GET['page']",
        'php:' . "\$_GET['page']",
        '95',
    ]);
    $errors = $this->processEvents([
        [
            'kind' => 'sink',
            'file' => $file,
            'scope' => '::file',
            'offset' => 12,
            'startOffset' => 10,
            'line' => 2,
            'expression' => "\$_GET['page']",
            'sources' => ['php:' . "\$_GET['page']"],
            'requestProbability' => 95,
            'unknown' => false,
            'variables' => [],
        ],
    ]);
    $error = $errors[0];

    expect($error->getIdentifier())->toBe('phpstanCwe.cwe98')
        ->and($error)->toBeInstanceOf(MetadataRuleError::class)
        ->and($error)->toBeInstanceOf(FileRuleError::class)
        ->and($error)->toBeInstanceOf(LineRuleError::class)
        ->and($error->getLine())->toBe(2)
        ->and($error->getFile())->toBe($file)
        ->and($error->getMetadata())->toBe([
            'cwe' => 98,
            'severity' => 'high',
            'probability' => 95,
            'url' => 'https://cwe.mitre.org/data/definitions/98.html',
            'fingerprint' => $fingerprint,
        ]);
});
