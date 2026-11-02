<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe89LaravelCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe89LaravelRule;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat as ConcatAssign;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\DNumber;
use PhpParser\Node\Scalar\EncapsedStringPart;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Testing\RuleTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\StringType;
use PHPStan\Type\Type;
use PHPStan\Type\UnionType;

class Cwe89LaravelCollectorTestCase extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new Cwe89LaravelRule();
    }
}

uses(Cwe89LaravelCollectorTestCase::class);

covers(Cwe89LaravelCollector::class);

function cwe89LaravelCollectorScope(
    string $resolvedName = 'Illuminate\\Support\\Facades\\DB',
    ?Type $receiverType = null,
): Scope {
    $scope = test()->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    $scope->method('resolveName')->willReturn($resolvedName);
    $scope->method('getType')->willReturn($receiverType ?? new MixedType());

    return $scope;
}

it('exposes its node type and ignores nodes that are not SQL sinks', function (): void {
    $collector = new Cwe89LaravelCollector();

    expect($collector->getNodeType())->toBe(PhpParser\Node::class)
        ->and($collector->processNode(
            new FuncCall(new Name('ordinaryFunction')),
            cwe89LaravelCollectorScope(),
        ))->toBeNull();
});

it('provides the supported Laravel classes, methods, and request variables', function (): void {
    expect(Cwe89LaravelCollector::getBuilderClasses())->toBe([
        'Illuminate\Database\Eloquent\Builder',
        'Illuminate\Database\Eloquent\Relations\Relation',
        'Illuminate\Database\Query\Builder',
    ])->and(Cwe89LaravelCollector::getRawMethods())->toBe([
        'fromraw',
        'groupbyraw',
        'havingraw',
        'orhavingraw',
        'orwhereraw',
        'orderbyraw',
        'selectraw',
        'whereraw',
    ])->and(Cwe89LaravelCollector::getRequestVariables())->toBe([
        '_GET',
        '_POST',
        '_COOKIE',
        '_REQUEST',
    ]);
});

it('collects assignments and tracks dynamic concatenation values', function (): void {
    $collector = new Cwe89LaravelCollector();
    $scope = cwe89LaravelCollectorScope();

    $requestAssignment = $collector->processNode(
        new Assign(new Variable('value'), new Variable('_GET')),
        $scope,
    );
    $concatAssignment = $collector->processNode(
        new ConcatAssign(
            new Variable('query'),
            new FuncCall(new Name('getUnknownValue')),
        ),
        $scope,
    );

    expect($requestAssignment)->toMatchArray([
        'kind' => 'assignment',
        'variable' => 'value',
        'dynamic' => true,
        'request' => true,
        'unknown' => false,
        'variables' => [],
    ])->and($concatAssignment)->toMatchArray([
        'kind' => 'assignment',
        'variable' => 'query',
        'dynamic' => true,
        'request' => false,
        'unknown' => true,
        'variables' => ['query'],
    ]);
});

it('recognizes every supported raw builder method', function (): void {
    $collector = new Cwe89LaravelCollector();
    $scope = cwe89LaravelCollectorScope(
        receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder'),
    );

    foreach ([
        'fromRaw',
        'groupByRaw',
        'havingRaw',
        'orHavingRaw',
        'orWhereRaw',
        'orderByRaw',
        'selectRaw',
        'whereRaw',
    ] as $method) {
        $event = $collector->processNode(
            new MethodCall(
                new Variable('builder'),
                new Identifier($method),
                [new Arg(new String_('SELECT 1'))],
            ),
            $scope,
        );

        expect($event)->toBeArray()
            ->and($event['kind'])->toBe('sink')
            ->and($event['dynamic'])->toBeFalse();
    }
});

it('recognizes supported builder classes and skips unsupported method calls', function (): void {
    $collector = new Cwe89LaravelCollector();

    foreach ([
        'Illuminate\\Database\\Query\\Builder',
        'Illuminate\\Database\\Eloquent\\Builder',
        'Illuminate\\Database\\Eloquent\\Relations\\Relation',
    ] as $builderClass) {
        $event = $collector->processNode(
            new MethodCall(
                new Variable('builder'),
                new Identifier('whereRaw'),
                [new Arg(new String_('SELECT 1'))],
            ),
            cwe89LaravelCollectorScope(receiverType: new ObjectType($builderClass)),
        );

        expect($event)->toBeArray()->and($event['kind'])->toBe('sink');
    }

    $unsupportedScope = cwe89LaravelCollectorScope(
        receiverType: new ObjectType('stdClass'),
    );

    expect($collector->processNode(
        new MethodCall(
            new Variable('builder'),
            new Identifier('whereRaw'),
            [new Arg(new String_('SELECT 1'))],
        ),
        $unsupportedScope,
    ))->toBeNull()
        ->and($collector->processNode(
            new MethodCall(
                new Variable('builder'),
                new Identifier('where'),
                [new Arg(new String_('id'))],
            ),
            cwe89LaravelCollectorScope(receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder')),
        ))->toBeNull()
        ->and($collector->processNode(
            new MethodCall(
                new Variable('builder'),
                new Variable('method'),
                [new Arg(new String_('SELECT 1'))],
            ),
            cwe89LaravelCollectorScope(receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder')),
        ))->toBeNull();
});

it('collects database facade queries with positional and named arguments', function (): void {
    $collector = new Cwe89LaravelCollector();

    foreach (['select', 'insert', 'update', 'delete'] as $method) {
        $event = $collector->processNode(
            new StaticCall(
                new Name\FullyQualified('Illuminate\\Support\\Facades\\DB'),
                new Identifier($method),
                [new Arg(new String_('SELECT 1'))],
            ),
            cwe89LaravelCollectorScope(),
        );

        expect($event)->toBeArray()->and($event['kind'])->toBe('sink');
    }

    $namedEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new String_('SELECT 1'), name: new Identifier('QUERY'))],
        ),
        cwe89LaravelCollectorScope('App\\DB'),
    );

    expect($namedEvent)->toBeArray()
        ->and($namedEvent['kind'])->toBe('sink')
        ->and($collector->processNode(
            new StaticCall(
                new Name('Other'),
                new Identifier('select'),
                [new Arg(new String_('SELECT 1'))],
            ),
            cwe89LaravelCollectorScope('App\\Other'),
        ))->toBeNull();
});

it('ignores unsupported SQL arguments and facade calls', function (): void {
    $collector = new Cwe89LaravelCollector();
    $builderScope = cwe89LaravelCollectorScope(
        receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder'),
    );

    expect($collector->processNode(
        new MethodCall(new Variable('builder'), new Identifier('whereRaw')),
        $builderScope,
    ))->toBeNull()
        ->and($collector->processNode(
            new MethodCall(
                new Variable('builder'),
                new Identifier('whereRaw'),
                [new Arg(new String_('SELECT 1'), name: new Identifier('bindings'))],
            ),
            $builderScope,
        ))->toBeNull()
        ->and($collector->processNode(
            new StaticCall(new Name('DB'), new Identifier('select')),
            cwe89LaravelCollectorScope(),
        ))->toBeNull()
        ->and($collector->processNode(
            new StaticCall(
                new Name('Other'),
                new Identifier('select'),
                [new Arg(new String_('SELECT 1'))],
            ),
            cwe89LaravelCollectorScope('App\\Other'),
        ))->toBeNull();
});

it('classifies literals, request inputs, variables, and dynamic variable names', function (): void {
    $collector = new Cwe89LaravelCollector();
    $scope = cwe89LaravelCollectorScope();

    foreach ([
        new String_('SELECT 1'),
        new LNumber(1),
        new DNumber(1.5),
    ] as $literal) {
        $event = $collector->processNode(
            new StaticCall(new Name('DB'), new Identifier('select'), [new Arg($literal)]),
            $scope,
        );

        expect($event)->toMatchArray([
            'dynamic' => false,
            'request' => false,
            'unknown' => false,
            'variables' => [],
        ]);
    }
    $interpolatedStringEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new PhpParser\Node\Scalar\InterpolatedString([new EncapsedStringPart('SELECT 1')]))],
        ),
        $scope,
    );

    $requestEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new Variable('_COOKIE'))],
        ),
        $scope,
    );
    $variableEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new Variable('query'))],
        ),
        $scope,
    );
    $dynamicVariableEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new Variable(new Variable('variableName')))],
        ),
        $scope,
    );

    expect($requestEvent)->toMatchArray([
        'dynamic' => true,
        'request' => true,
        'unknown' => false,
        'variables' => [],
    ])->and($interpolatedStringEvent)->toMatchArray([
        'dynamic' => false,
        'request' => false,
        'unknown' => false,
        'variables' => [],
    ])->and($variableEvent)->toMatchArray([
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['query'],
    ])->and($dynamicVariableEvent)->toMatchArray([
        'dynamic' => true,
        'request' => false,
        'unknown' => true,
        'variables' => [],
    ]);
});

it('tracks request helper calls and marks other dynamic expressions unknown', function (): void {
    $collector = new Cwe89LaravelCollector();
    $scope = cwe89LaravelCollectorScope();

    $requestEvent = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new FuncCall(new Name('request'), [new Arg(new String_('id'))]))],
        ),
        $scope,
    );

    expect($requestEvent)->toMatchArray([
        'dynamic' => true,
        'request' => true,
        'unknown' => false,
        'variables' => [],
    ]);

    $unknownExpressions = [
        new FuncCall(new Name('getenv'), [new Arg(new String_('SQL'))]),
        new MethodCall(new Variable('source'), new Identifier('value')),
        new StaticCall(new Name('Source'), new Identifier('value')),
        new Expr\New_(new Name('Source')),
        new Expr\PropertyFetch(new Variable('source'), new Identifier('value')),
        new Expr\NullsafePropertyFetch(new Variable('source'), new Identifier('value')),
    ];

    foreach ($unknownExpressions as $expression) {
        $event = $collector->processNode(
            new StaticCall(new Name('DB'), new Identifier('select'), [new Arg($expression)]),
            $scope,
        );

        expect($event)->toMatchArray([
            'dynamic' => true,
            'unknown' => true,
        ]);
    }
});

it('combines request and variable facts in compound expressions', function (): void {
    $collector = new Cwe89LaravelCollector();
    $event = $collector->processNode(
        new StaticCall(
            new Name('DB'),
            new Identifier('select'),
            [new Arg(new Expr\BinaryOp\Concat(
                new Variable('_REQUEST'),
                new Variable('suffix'),
            ))],
        ),
        cwe89LaravelCollectorScope(),
    );

    expect($event)->toMatchArray([
        'dynamic' => true,
        'request' => true,
        'unknown' => false,
        'variables' => ['suffix'],
    ]);
});

it('accepts grammar wrapping only for string arguments on a Laravel grammar', function (
    Type $receiverType,
    Type $argumentType,
    string $method,
    ?string $argumentName,
    bool $hasArgument,
    bool $isProtected,
): void {
    $column = new Variable('column');
    $grammar = new Variable('grammar');
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/laravel.php');
    // Give each expression its test type without loading Laravel.
    $scope->method('getType')->willReturnCallback(
        static fn (Expr $expression): Type => $expression === $grammar ? $receiverType : $argumentType,
    );
    $arguments = $hasArgument
        ? [new Arg($column, name: $argumentName === null ? null : new Identifier($argumentName))]
        : [];
    // Collect an assignment to check the facts stored for later SQL calls.
    $event = (new Cwe89LaravelCollector())->processNode(
        new Assign(
            new Variable('wrappedColumn'),
            new MethodCall($grammar, new Identifier($method), $arguments),
        ),
        $scope,
    );

    // A protected result must not retain its input variables as SQL sources.
    expect($event)->toMatchArray([
        'dynamic' => !$isProtected,
        'request' => false,
        'unknown' => !$isProtected,
        'variables' => $isProtected ? [] : ($hasArgument ? ['grammar', 'column'] : ['grammar']),
    ]);
})->with([
    // These cases use Laravel identifier quoting with a string argument.
    'string column' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'wrap', null, true, true],
    'named column' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'wrap', 'value', true, true],
    'method case' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'WRAP', null, true, true],
    // These cases do not prove that Laravel quotes the input as an identifier.
    'raw expression' => [new ObjectType('Illuminate\Database\Grammar'), new ObjectType('Illuminate\Database\Query\Expression'), 'wrap', null, true, false],
    'possible raw expression' => [new ObjectType('Illuminate\Database\Grammar'), new UnionType([new StringType(), new ObjectType('Illuminate\Database\Query\Expression')]), 'wrap', null, true, false],
    'unknown argument' => [new ObjectType('Illuminate\Database\Grammar'), new MixedType(), 'wrap', null, true, false],
    'other receiver' => [new ObjectType('stdClass'), new StringType(), 'wrap', null, true, false],
    'unknown receiver' => [new MixedType(), new StringType(), 'wrap', null, true, false],
    'other method' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'quoteString', null, true, false],
    'no argument' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'wrap', null, false, false],
    'wrong named argument' => [new ObjectType('Illuminate\Database\Grammar'), new StringType(), 'wrap', 'other', true, false],
]);

it('keeps the complete event shape and source position', function (): void {
    $function = $this->createStub(PHPStan\Reflection\Php\PhpFunctionFromParserNodeReflection::class);
    $function->method('getName')->willReturn('findUsers');
    $class = $this->getContainer()->getByType(PHPStan\Reflection\ReflectionProvider::class)->getClass(stdClass::class);
    $scope = cwe89LaravelCollectorScope();
    $scope->method('getFunction')->willReturn($function);
    $scope->method('getClassReflection')->willReturn($class);
    $collector = new Cwe89LaravelCollector();
    $assignment = new Assign(new Variable('query'), new String_('SELECT 1'), ['endTokenPos' => 19]);
    $sink = new StaticCall(new Name('DB'), new Identifier('SELECT'), [
        new Arg(new Variable('query'), name: new Identifier('sql')),
    ], ['startTokenPos' => 31, 'startLine' => 7]);

    expect($collector->processNode($assignment, $scope))->toBe([
        'kind' => 'assignment',
        'file' => '/tmp/laravel.php',
        'scope' => 'stdClass::findUsers',
        'offset' => 19,
        'variable' => 'query',
        'dynamic' => false,
        'request' => false,
        'unknown' => false,
        'variables' => [],
    ])->and($collector->processNode($sink, $scope))->toBe([
        'kind' => 'sink',
        'file' => '/tmp/laravel.php',
        'scope' => 'stdClass::findUsers',
        'offset' => 31,
        'line' => 7,
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['query'],
    ]);
});

it('records a file scope and reads the old value for literal concatenation', function (): void {
    $event = (new Cwe89LaravelCollector())->processNode(
        new ConcatAssign(new Variable('query'), new String_(' LIMIT 1'), ['endTokenPos' => 25]),
        cwe89LaravelCollectorScope(),
    );

    expect($event)->toBe([
        'kind' => 'assignment',
        'file' => '/tmp/laravel.php',
        'scope' => '::file',
        'offset' => 25,
        'variable' => 'query',
        'dynamic' => true,
        'request' => false,
        'unknown' => false,
        'variables' => ['query'],
    ]);
});

it('rejects dynamic assignment targets and dynamic call names', function (): void {
    $collector = new Cwe89LaravelCollector();
    $scope = cwe89LaravelCollectorScope(receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder'));

    foreach ([
        new Assign(new Expr\ArrayDimFetch(new Variable('queries'), new String_('query')), new String_('SQL')),
        new Assign(new Expr\PropertyFetch(new Variable('object'), 'query'), new String_('SQL')),
        new Assign(new Variable(new Variable('name')), new String_('SQL')),
        new StaticCall(new Name('DB'), new Variable('method'), [new Arg(new String_('SQL'))]),
        new StaticCall(new Variable('class'), new Identifier('select'), [new Arg(new String_('SQL'))]),
        new StaticCall(new Name('DB'), new Identifier('statement'), [new Arg(new String_('SQL'))]),
        new StaticCall(new Name\FullyQualified('Other\\DB'), new Identifier('select'), [new Arg(new String_('SQL'))]),
        new MethodCall(new Variable('builder'), new Variable('method'), [new Arg(new String_('SQL'))]),
        new StaticCall(new Name('DB'), new Identifier('select'), [new PhpParser\Node\VariadicPlaceholder()]),
    ] as $node) {
        $nodeScope = $node instanceof StaticCall && $node->class instanceof Name\FullyQualified
            ? cwe89LaravelCollectorScope('Other\\DB')
            : $scope;
        expect($collector->processNode($node, $nodeScope))->toBeNull();
    }
});

it('reads all supported named SQL arguments after other arguments', function (bool $isBuilder, string $name): void {
    $arguments = [
        new Arg(new Expr\Array_(), name: new Identifier('bindings')),
        new Arg(new Variable('_GET'), name: new Identifier($name)),
    ];
    $call = $isBuilder
        ? new MethodCall(new Variable('builder'), new Identifier('whereRaw'), $arguments)
        : new StaticCall(new Name('DB'), new Identifier('select'), $arguments);
    $event = (new Cwe89LaravelCollector())->processNode(
        $call,
        cwe89LaravelCollectorScope(receiverType: new ObjectType('Illuminate\\Database\\Query\\Builder')),
    );

    expect($event)->toMatchArray(['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []]);
})->with([
    'builder sql' => [true, 'sql'],
    'builder expression' => [true, 'expression'],
    'facade query' => [false, 'query'],
    'facade sql' => [false, 'sql'],
]);

it('keeps distinct variable names in first occurrence order', function (): void {
    $expression = new Expr\BinaryOp\Concat(
        new Variable('first'),
        new Expr\BinaryOp\Concat(new Variable('first'), new Variable('second')),
    );
    $event = (new Cwe89LaravelCollector())->processNode(new Assign(new Variable('query'), $expression), cwe89LaravelCollectorScope());

    expect($event['variables'])->toBe(['first', 'second']);
});

it('reads array children and skips empty array items', function (): void {
    $event = (new Cwe89LaravelCollector())->processNode(
        new Assign(new Variable('query'), new Expr\Array_([null, new PhpParser\Node\ArrayItem(new Variable('_GET'))])),
        cwe89LaravelCollectorScope(),
    );
    expect($event)->toMatchArray(['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []]);
});

it('does not classify dynamic functions as the request helper', function (): void {
    $collector = new Cwe89LaravelCollector();
    foreach ([
        new FuncCall(new Variable('function'), [new Arg(new Variable('_GET'))]),
        new MethodCall(new Variable('grammar'), new Variable('method'), [new Arg(new Variable('_GET'))]),
        new FuncCall(new Name('REQUEST'), [new Arg(new Variable('key'))]),
    ] as $expression) {
        $event = $collector->processNode(new Assign(new Variable('query'), $expression), cwe89LaravelCollectorScope());
        expect($event['dynamic'])->toBeTrue()->and($event['request'])->toBeTrue();
    }

    $event = $collector->processNode(
        new Assign(new Variable('query'), new FuncCall(new Variable('function'), [new Arg(new String_('id'))])),
        cwe89LaravelCollectorScope(),
    );
    expect($event['request'])->toBeFalse()->and($event['unknown'])->toBeTrue();
});
