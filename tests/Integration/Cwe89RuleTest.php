<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\RequestInput;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89Rule;
use PhpParser\Node;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;

class Cwe89RuleTestCase extends RuleTestCase
{
    use AnalysesWithoutFingerprints;

    private int $minimumProbability = 0;

    protected function getRule(): Rule
    {
        return $this->makeRule($this->minimumProbability);
    }

    protected function getCollectors(): array
    {
        return [
            $this->makeCollector(),
            new CweIgnoreCollector(),
        ];
    }

    public function makeRule(int $minimumProbability = 0): Cwe89Rule
    {
        return new Cwe89Rule($minimumProbability);
    }

    public function makeCollector(): Cwe89Collector
    {
        return new Cwe89Collector($this->getContainer()->getByType(ReflectionProvider::class));
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

    public function collect(Node $node, ?PHPStan\Analyser\Scope $scope = null): ?array
    {
        return $this->makeCollector()->processNode($node, $scope ?? $this->createStub(PHPStan\Analyser\Scope::class));
    }
}

uses(Cwe89RuleTestCase::class);

covers(Cwe89Rule::class, Cwe89Collector::class, RequestInput::class);

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
    expect(fn () => $this->makeRule(101))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $this->makeRule(-1))->toThrow(InvalidArgumentException::class);
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

    expect($this->collect($placeholderCall))->toBeNull()
        ->and($this->collect($missingQueryCall))->toBeNull();
});

it('has a default probability of 80', function (): void {
    expect(Cwe89Rule::getRequestProbability())->toBe(80);
});

it('uses zero as the default minimum probability', function (): void {
    expect(invade(new Cwe89Rule())->minProbability)->toBe(0)
        ->and(invade($this->makeRule(50))->minProbability)->toBe(50);
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
    $scope->method('getFile')->willReturn('/tmp/sql.php');
    $event = $this->collect($node, $scope);

    expect($event)->not->toBeNull()
        ->and($event['file'])->toBe('/tmp/sql.php')
        ->and($event['scope'])->toBe('::file')
        ->and($event['expression'])->toStartWith(strtolower($method) . ': ');
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
        expect($this->collect($node, $scope))->toBeNull();
    }
});

it('puts the class, function, and file scope into the direct sink identity', function (): void {
    $provider = $this->getContainer()->getByType(ReflectionProvider::class);
    $makeScope = function (?string $class, ?string $function) use ($provider): PHPStan\Analyser\Scope {
        $scope = $this->createStub(PHPStan\Analyser\Scope::class);
        $scope->method('getFile')->willReturn('f.php');
        $scope->method('getClassReflection')->willReturn($class === null ? null : $provider->getClass($class));
        $reflection = null;
        if ($function !== null) {
            $reflection = $this->createStub(PHPStan\Reflection\Php\PhpFunctionFromParserNodeReflection::class);
            $reflection->method('getName')->willReturn($function);
        }
        $scope->method('getFunction')->willReturn($reflection);

        return $scope;
    };
    $call = static fn (string $function, PhpParser\Node\Expr $query): PhpParser\Node\Expr\FuncCall => new PhpParser\Node\Expr\FuncCall(
        new PhpParser\Node\Name($function),
        [new PhpParser\Node\Arg(new PhpParser\Node\Expr\Variable('c')), new PhpParser\Node\Arg($query)],
        ['startTokenPos' => 7, 'startLine' => 9],
    );
    $input = new PhpParser\Node\Expr\ArrayDimFetch(new PhpParser\Node\Expr\Variable('_GET'), new PhpParser\Node\Scalar\String_('q'));

    expect($this->collect($call('MYSQLI_QUERY', $input), $makeScope(stdClass::class, 'find')))->toBe([
        'file' => 'f.php',
        'scope' => 'stdClass::find',
        'offset' => 7,
        'line' => 9,
        'expression' => 'mysqli_query: $_GET[\'q\']',
    ])
        ->and($this->collect($call('mysqli_query', $input), $makeScope(null, null))['scope'])->toBe('::file')
        ->and($this->collect($call('mysqli_query', $input), $makeScope(stdClass::class, null))['scope'])->toBe('stdClass::file')
        ->and($this->collect($call('mysqli_query', $input), $makeScope(null, 'run'))['scope'])->toBe('::run');
});
