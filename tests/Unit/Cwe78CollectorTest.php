<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78IgnoreCollector;
use Perturbatio\PhpstanCwe\LaravelRequestInput;
use PhpParser\Node\Arg;
use PhpParser\Node\ArgPlaceholder;
use PhpParser\Comment;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\ShellExec;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\VariadicPlaceholder;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPUnit\Framework\TestCase;

class Cwe78CollectorTestCase extends TestCase
{
    protected function collector(): Cwe78Collector
    {
        $provider = $this->createStub(ReflectionProvider::class);
        $provider->method('resolveFunctionName')->willReturnCallback(
            static fn (Name $name): string => $name->toString(),
        );

        return new Cwe78Collector($provider);
    }

    protected function collectorWithResolvedFunction(?string $resolvedFunction): Cwe78Collector
    {
        $provider = $this->createStub(ReflectionProvider::class);
        $provider->method('resolveFunctionName')->willReturn($resolvedFunction);

        return new Cwe78Collector($provider);
    }

    protected function collectorWithUnknownEscapeFunction(): Cwe78Collector
    {
        $provider = $this->createStub(ReflectionProvider::class);
        $provider->method('resolveFunctionName')->willReturnCallback(
            static fn (Name $name): ?string => strtolower($name->toString()) === 'escapeshellarg'
                ? null
                : $name->toString(),
        );

        return new Cwe78Collector($provider);
    }

    protected function scope(): Scope
    {
        $scope = $this->createStub(Scope::class);
        $scope->method('getFile')->willReturn('/tmp/cwe78.php');

        return $scope;
    }
}

uses(Cwe78CollectorTestCase::class);

covers(Cwe78Collector::class, Cwe78IgnoreCollector::class);

it('provides a node type and collects assignments with request data', function (): void {
    $collector = $this->collector();
    $scope = $this->scope();
    $scope->method('getFunctionName')->willReturn('Example::run');
    $assignment = new Assign(
        new Variable('command'),
        new ArrayDimFetch(new Variable('_GET'), new String_('command')),
    );
    $event = $collector->processNode($assignment, $scope);

    expect(Cwe78Collector::getSupportedFunctions())->toBe([
        'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open',
    ])
        ->and(Cwe78Collector::getRequestVariables())->toBe(['_GET', '_POST', '_COOKIE', '_REQUEST'])
        ->and($collector->getNodeType())->toBe(PhpParser\Node::class)
        ->and($event)->toBe([
            'kind' => 'assignment',
            'file' => '/tmp/cwe78.php',
            'scope' => 'Example::run',
            'offset' => -1,
            'variable' => 'command',
            'request' => true,
            'hasStaticText' => false,
            'variables' => [],
        ]);
});

it('tracks concatenation assignments and command functions', function (): void {
    $collector = $this->collector();
    $scope = $this->scope();
    $assignment = new Concat(new Variable('command'), new String_(' tail'));
    $assignmentEvent = $collector->processNode($assignment, $scope);
    $call = new FuncCall(
        new Name('exec'),
        [new Arg(new PhpParser\Node\Expr\BinaryOp\Concat(
            new String_('tool '),
            new ArrayDimFetch(new Variable('_POST'), new String_('value')),
        ))],
        ['startLine' => 5, 'startTokenPos' => 3],
    );
    $sinkEvent = $collector->processNode($call, $scope);

    expect($assignmentEvent)->toMatchArray([
        'kind' => 'assignment',
        'variable' => 'command',
        'hasStaticText' => true,
        'variables' => ['command'],
    ])
        ->and($sinkEvent)->toBe([
            'kind' => 'sink',
            'file' => '/tmp/cwe78.php',
            'scope' => 'file',
            'offset' => 3,
            'line' => 5,
            'request' => true,
            'hasStaticText' => true,
            'throughAssignment' => false,
            'variables' => [],
        ])
        ->and($collector->processNode(new FuncCall(new Name('unknown'), []), $scope))->toBeNull()
        ->and($collector->processNode(new PhpParser\Node\Expr\ConstFetch(new Name('exec')), $scope))->toBeNull()
        ->and($collector->processNode(
            new Assign(new Variable(new Variable('variableName')), new String_('fixed')),
            $scope,
        ))->toBeNull()
        ->and($collector->processNode(
            new Assign(
                new PropertyFetch(new Variable('command'), 'name'),
                new String_('fixed'),
            ),
            $scope,
        ))->toBeNull()
        ->and($collector->processNode(
            new Assign(
                new Variable('target'),
                new PhpParser\Node\Expr\BinaryOp\Concat(new Variable('_GET'), new Variable('command')),
            ),
            $scope,
        ))->toMatchArray(['request' => true, 'variables' => ['command']])
        ->and($collector->processNode(
            new Concat(new Variable('_GET'), new Variable('command')),
            $scope,
        ))->toMatchArray(['request' => true, 'variables' => ['command', '_GET']])
        ->and($collector->processNode(
            new Concat(
                new Variable('command'),
                new PhpParser\Node\Expr\BinaryOp\Concat(new Variable('command'), new String_(' tail')),
            ),
            $scope,
        )['variables'])->toBe(['command']);
});

it('collects Laravel request input facts', function (): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(
        static fn (Name $name): string => $name->toString(),
    );
    $scope = $this->scope();
    $input = new FuncCall(
        new Name('request'),
        [new Arg(new String_('command'))],
    );
    $collector = new Cwe78Collector($provider, new LaravelRequestInput($provider));

    expect($collector->processNode(
        new Assign(new Variable('command'), $input),
        $scope,
    ))->toMatchArray(['kind' => 'assignment', 'request' => true]);
});

it('recognizes escaped values, named commands, process arrays, and backticks', function (): void {
    $collector = $this->collector();
    $scope = $this->scope();
    $escaped = new FuncCall(
        new Name('exec'),
        [new Arg(new FuncCall(new Name('escapeshellarg'), [new Arg(new Variable('_GET'))]))],
    );
    $named = new FuncCall(new Name('exec'), [new Arg(new Variable('_REQUEST'), name: new PhpParser\Node\Identifier('command'))]);
    $processArray = new FuncCall(
        new Name('proc_open'),
        [new Arg(new PhpParser\Node\Expr\Array_([
            new PhpParser\Node\ArrayItem(new String_('tool')),
            new PhpParser\Node\ArrayItem(new Variable('_GET')),
        ]))],
    );
    $backtick = new ShellExec([new InterpolatedStringPart('tool '), new Variable('command')]);
    $emptyProcessArray = new FuncCall(
        new Name('proc_open'),
        [new Arg(new PhpParser\Node\Expr\Array_())],
    );
    $namedAfterOtherNamed = new FuncCall(
        new Name('exec'),
        [
            new Arg(new String_('unused'), name: new PhpParser\Node\Identifier('other')),
            new Arg(new Variable('_REQUEST'), name: new PhpParser\Node\Identifier('COMMAND')),
        ],
    );
    $uppercaseFunction = new FuncCall(new Name('EXEC'), [new Arg(new String_('fixed'))]);
    $uppercaseEscape = new FuncCall(
        new Name('exec'),
        [new Arg(new FuncCall(new Name('ESCAPESHELLARG'), [new Arg(new Variable('_GET'))]))],
    );
    $placeholderBeforeCommand = new FuncCall(
        new Name('exec'),
        [new ArgPlaceholder(), new Arg(new String_('fixed'))],
    );
    $invalidFunctionName = new FuncCall(new Variable('functionName'), [new Arg(new String_('fixed'))]);
    $unresolvedFunction = new FuncCall(new Name('exec'), [new Arg(new String_('fixed'))]);
    $dynamicEscapeFunction = new FuncCall(
        new Name('exec'),
        [new Arg(new FuncCall(new Variable('escapeFunction'), [new Arg(new Variable('_GET'))]))],
    );
    $procOpenString = new FuncCall(
        new Name('proc_open'),
        [new Arg(new PhpParser\Node\Expr\BinaryOp\Concat(new String_('tool '), new Variable('_GET')))],
    );
    $arrayDimensions = new FuncCall(
        new Name('exec'),
        [new Arg(new ArrayDimFetch(
            new Variable('commands'),
            new PhpParser\Node\Expr\BinaryOp\Concat(
                new Variable('commands'),
                new PhpParser\Node\Expr\BinaryOp\Concat(new Variable('commands'), new Variable('index')),
            ),
        ))],
    );
    $duplicateConcat = new FuncCall(
        new Name('exec'),
        [new Arg(new Concat(
            new Variable('commands'),
            new PhpParser\Node\Expr\BinaryOp\Concat(new Variable('commands'), new Variable('index')),
        ))],
    );
    $arrayCommandToOtherFunction = new FuncCall(
        new Name('exec'),
        [new Arg(new PhpParser\Node\Expr\Array_([
            new PhpParser\Node\ArrayItem(new String_('tool')),
            new PhpParser\Node\ArrayItem(new Variable('_GET')),
        ]))],
    );
    $emptyArrayItem = new FuncCall(
        new Name('exec'),
        [new Arg(new PhpParser\Node\Expr\Array_([null]))],
    );

    expect($collector->processNode($escaped, $scope))->toMatchArray([
        'kind' => 'sink',
        'request' => false,
        'hasStaticText' => false,
    ])
        ->and($collector->processNode($named, $scope))->toMatchArray([
            'kind' => 'sink',
            'request' => true,
        ])
        ->and($collector->processNode($processArray, $scope))->toMatchArray([
            'kind' => 'sink',
            'request' => false,
            'hasStaticText' => true,
        ])
        ->and($collector->processNode($emptyProcessArray, $scope))->toMatchArray([
            'kind' => 'sink',
            'request' => false,
            'hasStaticText' => false,
        ])
        ->and($collector->processNode($backtick, $scope))->toMatchArray([
            'kind' => 'sink',
            'hasStaticText' => true,
            'variables' => ['command'],
        ])
        ->and($collector->processNode($namedAfterOtherNamed, $scope))->toMatchArray(['request' => true])
        ->and($collector->processNode($uppercaseFunction, $scope))->toMatchArray(['kind' => 'sink'])
        ->and($collector->processNode($uppercaseEscape, $scope))->toMatchArray([
            'request' => false,
            'hasStaticText' => false,
        ])
        ->and($collector->processNode($placeholderBeforeCommand, $scope))->toMatchArray(['kind' => 'sink'])
        ->and($collector->processNode($invalidFunctionName, $scope))->toBeNull()
        ->and($collector->processNode($arrayDimensions, $scope)['variables'])->toBe(['commands', 'index'])
        ->and($collector->processNode($duplicateConcat, $scope)['variables'])->toBe(['commands', 'index'])
        ->and($collector->processNode($arrayCommandToOtherFunction, $scope))->toMatchArray([
            'request' => true,
            'hasStaticText' => true,
        ])
        ->and($collector->processNode($procOpenString, $scope))->toMatchArray([
            'request' => true,
            'hasStaticText' => true,
        ])
        ->and($this->collectorWithResolvedFunction('PROC_OPEN')->processNode($processArray, $scope))->toMatchArray([
            'request' => false,
            'hasStaticText' => true,
        ])
        ->and($collector->processNode($emptyArrayItem, $scope))->toMatchArray(['kind' => 'sink'])
        ->and($collector->processNode($dynamicEscapeFunction, $scope))->toMatchArray(['request' => true])
        ->and($this->collectorWithResolvedFunction(null)->processNode($unresolvedFunction, $scope))->toBeNull()
        ->and($this->collectorWithUnknownEscapeFunction()->processNode(
            new FuncCall(
                new Name('exec'),
                [new Arg(new FuncCall(new Name('escapeshellarg'), [new Arg(new Variable('_GET'))]))],
            ),
            $scope,
        ))->toMatchArray(['request' => true])
        ->and($collector->processNode(
            new FuncCall(new Name('exec'), [new ArgPlaceholder()]),
            $scope,
        ))->toBeNull()
        ->and($collector->processNode(
            new FuncCall(new Name('exec'), [new VariadicPlaceholder()]),
            $scope,
        ))->toBeNull()
        ->and($collector->processNode(
            new FuncCall(new Name('proc_open'), [new Arg(new PhpParser\Node\Expr\Array_())]),
            $scope,
        ))->toMatchArray(['kind' => 'sink', 'request' => false])
        ->and($collector->processNode(
            new FuncCall(new Name('exec'), [
                new Arg(new ArrayDimFetch(new Variable('_GET'), null)),
            ]),
            $scope,
        ))->toMatchArray(['kind' => 'sink', 'request' => true, 'hasStaticText' => false])
        ->and($collector->processNode(
            new FuncCall(new Name('exec'), [
                new Arg(new ArrayDimFetch(new Variable('commands'), null)),
            ]),
            $scope,
        ))->toMatchArray(['kind' => 'sink', 'request' => false, 'hasStaticText' => false]);
});

it('collects CWE-78 ignore reasons only from matching statement comments', function (): void {
    $parser = (new PhpParser\ParserFactory())->createForNewestSupportedVersion();
    $valid = $parser->parse("<?php\n// @phpstan-ignore phpstanCwe.cwe78 (This uses user@host input)\nexec('fixed');");
    $other = $parser->parse("<?php\n// @phpstan-ignore phpstanCwe.cwe79 (fixed local output)\necho 'fixed';");
    $missingReason = $parser->parse("<?php\n// @phpstan-ignore phpstanCwe.cwe78\nexec('fixed');");
    $ordinaryComment = $parser->parse("<?php\n// ordinary comment\nexec('fixed');");
    $spacedReason = $parser->parse("<?php\n// @phpstan-ignore phpstanCwe.cwe78 (  two words  )\nexec('fixed');");
    $multipleComments = new Expression(
        new FuncCall(new Name('exec'), []),
        [
            'comments' => [
                new Comment('// unrelated comment'),
                new Comment('// @phpstan-ignore phpstanCwe.cwe78 (two words)'),
            ],
        ],
    );
    $nonExpressionWithIgnore = new PhpParser\Node\Stmt\Return_(
        expr: null,
        attributes: [
            'comments' => [
                new Comment('// @phpstan-ignore phpstanCwe.cwe78 (two words)'),
            ],
        ],
    );
    $collector = new Cwe78IgnoreCollector();
    $scope = $this->scope();

    expect($collector->getNodeType())->toBe(PhpParser\Node::class)
        ->and($collector->processNode($valid[0], $scope))->toBe([
            'file' => '/tmp/cwe78.php',
            'line' => 2,
            'reason' => 'This uses user@host input',
        ])
        ->and($collector->processNode($other[0], $scope))->toBeNull()
        ->and($collector->processNode($missingReason[0], $scope))->toMatchArray(['reason' => ''])
        ->and($collector->processNode($ordinaryComment[0], $scope))->toBeNull()
        ->and($collector->processNode($spacedReason[0], $scope))->toMatchArray(['reason' => 'two words'])
        ->and($collector->processNode($multipleComments, $scope))->toMatchArray(['reason' => 'two words'])
        ->and($collector->processNode(new Expression(new FuncCall(new Name('exec'), [])), $scope))->toBeNull()
        ->and($collector->processNode($nonExpressionWithIgnore, $scope))->toBeNull()
        ->and($collector->processNode(new PhpParser\Node\Stmt\Return_(), $scope))->toBeNull();
});
