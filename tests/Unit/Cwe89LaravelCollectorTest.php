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
use PHPStan\Type\Type;

class Cwe89LaravelCollectorTestCase extends RuleTestCase
{
    protected function getRule(): Rule
    {
        return new Cwe89LaravelRule();
    }
}

uses(Cwe89LaravelCollectorTestCase::class);

function cwe89LaravelCollectorScope(
    string $resolvedName = 'Illuminate\\Support\\Facades\\DB',
    ?Type $receiverType = null,
): Scope {
    $scope = test()->createMock(Scope::class);
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
