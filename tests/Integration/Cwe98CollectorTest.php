<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe98\Cwe98Collector;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Testing\PHPStanTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\ObjectType;
use PHPStan\Type\ArrayType;
use PHPStan\Type\StringType;

uses(PHPStanTestCase::class);

covers(Cwe98Collector::class);

class Cwe98NamedExpression extends Expr
{
    public string $name = 'files';

    public function getSubNodeNames(): array
    {
        return [];
    }

    public function getType(): string
    {
        return 'Expr_Cwe98NamedExpression';
    }
}

it('keeps the highest non-null request probability when merging facts', function (?int $left, ?int $right, ?int $expected): void {
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $facts = ['sources' => [], 'unknown' => false, 'variables' => []];

    expect(invade($collector)->mergeFacts(
        [...$facts, 'requestProbability' => $left],
        [...$facts, 'requestProbability' => $right],
    )['requestProbability'])->toBe($expected);
})->with([
    'no request input' => [null, null, null],
    'left input only' => [95, null, 95],
    'right input only' => [null, 85, 85],
    'left input has higher score' => [95, 45, 95],
    'right input has higher score' => [45, 85, 85],
    'zero score is not null' => [null, 0, 0],
    'negative score is not null' => [null, -1, -1],
]);

it('collects include filename facts for request sources and dynamic expressions', function (
    string $expression,
    array $sources,
    ?int $probability,
    bool $unknown,
    array $variables,
): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(
        static fn (Node\Name $name): string => $name->toString(),
    );
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $scope->method('getType')->willReturnCallback(
        static fn (Expr $node) => $node instanceof Expr\Variable && $node->name === 'request'
            ? new ObjectType('Illuminate\Http\Request')
            : new MixedType(),
    );
    $nodes = (new ParserFactory())->createForHostVersion()->parse("<?php\ninclude {$expression};");
    $sink = $nodes[0]->expr;
    $collector = new Cwe98Collector($provider);

    expect($collector->getNodeType())->toBe(Node::class)
        ->and($collector->processNode($sink, $scope))->toBe([
            'kind' => 'sink',
            'file' => '/tmp/include.php',
            'scope' => '::file',
            'offset' => $sink->getEndTokenPos(),
            'startOffset' => $sink->getStartTokenPos(),
            'line' => 2,
            'expression' => (new PhpParser\PrettyPrinter\Standard())->prettyPrintExpr($sink->expr),
            'sources' => $sources,
            'requestProbability' => $probability,
            'unknown' => $unknown,
            'variables' => $variables,
        ]);
})->with([
    'nested PHP request' => ['$_GET["pages"]["file"]', ['php:$_GET["pages"]["file"]'], 95, false, []],
    'whole PHP request' => ['$_POST', ['php:$_POST'], 95, false, []],
    'Laravel helper' => ['request("page")', ['laravel:request("page")'], 95, false, []],
    'Laravel method' => ['$request->input("page")', ['laravel:$request->input("page")'], 95, false, []],
    'fixed filename' => ['"home.php"', [], null, false, []],
    'local value' => ['$page', [], null, false, ['page' => 95]],
    'dynamic variable' => ['$$name', [], null, true, []],
    'known function with fixed path' => ['dirname("home.php")', [], null, false, []],
    'upper case known function' => ['BASENAME("home.php")', [], null, false, []],
    'Laravel resource path with fixed argument' => ['resource_path("home.php")', [], null, false, []],
    'unknown function with fixed path' => ['transform("home.php")', [], null, true, []],
    'dynamic function with fixed path' => ['$function("home.php")', [], null, true, []],
    'constructor with fixed argument' => ['new Example("home.php")', [], null, true, []],
    'property' => ['$object->file', [], null, true, ['object' => 95]],
    'nullsafe property' => ['$object?->file', [], null, true, ['object' => 95]],
    'transformed PHP input' => ['basename($_GET["file"])', ['php:$_GET["file"]'], 85, false, []],
    'integer cast' => ['(int) $_GET["file"]', ['php:$_GET["file"]'], 45, false, []],
    'float cast' => ['(float) $_GET["file"]', ['php:$_GET["file"]'], 45, false, []],
    'numeric then function' => ['(int) basename($_GET["file"])', ['php:$_GET["file"]'], 45, false, []],
    'function then numeric' => ['basename((int) $_GET["file"])', ['php:$_GET["file"]'], 45, false, []],
    'stronger source wins' => ['basename($_GET["file"]) . $_POST["suffix"]', ['php:$_GET["file"]', 'php:$_POST["suffix"]'], 95, false, []],
    'duplicate sources' => ['$_GET["file"] . $_GET["file"]', ['php:$_GET["file"]'], 95, false, []],
    'overlapping sources have consecutive keys' => [
        '($_GET["a"] . $_POST["b"]) . ($_GET["a"] . $_COOKIE["c"])',
        ['php:$_GET["a"]', 'php:$_POST["b"]', 'php:$_COOKIE["c"]'], 95, false, [],
    ],
    'duplicate variables keep strongest modifier' => ['basename($file) . $file', [], null, false, ['file' => 95]],
    'duplicate variables with stronger modifier first' => ['$file . basename($file)', [], null, false, ['file' => 95]],
    'separate variables' => ['$file . $suffix', [], null, false, ['file' => 95, 'suffix' => 95]],
    'unknown on left' => ['transform("home.php") . "fixed"', [], null, true, []],
    'unknown on right' => ['"fixed" . transform("home.php")', [], null, true, []],
    'match selector with fixed results' => ['match ($_GET["page"]) { default => "home.php" }', [], null, false, []],
    'match input result' => ['match ($choice) { 1 => $_GET["page"], default => "home.php" }', ['php:$_GET["page"]'], 95, false, []],
    'match multiple input results' => ['match ($choice) { 1 => $_GET["page"], default => $_POST["page"] }', ['php:$_GET["page"]', 'php:$_POST["page"]'], 95, false, []],
    'ternary selector with fixed results' => ['$_GET["page"] ? "home.php" : "help.php"', [], null, false, []],
    'ternary input result' => ['$choice ? $_GET["page"] : "home.php"', ['php:$_GET["page"]'], 95, false, []],
    'shorthand ternary' => ['$_GET["page"] ?: "home.php"', ['php:$_GET["page"]'], 95, false, []],
    'uncalled closure' => ['function () { return $_GET["page"]; }', [], null, true, []],
    'called arrow fallback' => ['(fn () => $_GET["page"])()', ['request input'], 95, true, []],
    'untracked callable' => ['$callback()', [], null, true, []],
]);

it('records scope boundaries and assignment dependencies', function (bool $arrow): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $attributes = ['startTokenPos' => 10, 'endTokenPos' => 30];
    $closure = $arrow
        ? new Expr\ArrowFunction(['expr' => new Expr\Variable('page')], $attributes)
        : new Expr\Closure([], $attributes);
    $assignment = new Expr\AssignOp\Concat(
        new Expr\Variable('file'),
        new Expr\BinaryOp\Concat(new Expr\Variable('file'), new Expr\Variable('suffix')),
        ['startTokenPos' => 5, 'endTokenPos' => 9],
    );

    expect($collector->processNode($closure, $scope))->toBe([
        'kind' => 'scope',
        'file' => '/tmp/include.php',
        'scope' => '::file',
        'offset' => 10,
        'endOffset' => 30,
    ])->and($collector->processNode($assignment, $scope))->toBe([
        'kind' => 'assignment',
        'file' => '/tmp/include.php',
        'scope' => '::file',
        'offset' => 9,
        'startOffset' => 5,
        'variable' => 'file',
        'sources' => [],
        'requestProbability' => null,
        'unknown' => false,
        'variables' => ['file' => 95, 'suffix' => 95],
    ]);
})->with([false, true]);

it('marks a foreach array and its value as unknown when it uses a reference', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php foreach ($files as &$file) {}');
    $event = $collector->processNode($nodes[0], $scope);

    $assignment = [
        'kind' => 'assignment', 'file' => '/tmp/include.php', 'scope' => '::file',
        'offset' => $nodes[0]->valueVar->getEndTokenPos(), 'startOffset' => $nodes[0]->getStartTokenPos(),
        'variable' => 'file', 'sources' => [], 'requestProbability' => null,
        'unknown' => true, 'variables' => ['files' => 95],
    ];
    expect($event)->toBe([
        'kind' => 'extraAssignments', 'file' => '/tmp/include.php', 'scope' => '::file',
        'assignments' => [[...$assignment, 'variable' => 'files'], $assignment],
    ]);
});

it('records route parameter assignment events with their identity and location', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $scope->method('resolveName')->willReturn('Illuminate\Support\Facades\Route');
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php Route::get("/{page}/{section}", function ($page, $section) {});',
    );
    $call = $nodes[0]->expr;
    $parameters = $call->args[1]->value->params;
    $assignments = [];
    foreach (['page', 'section'] as $index => $name) {
        $assignments[] = [
            'kind' => 'assignment', 'file' => '/tmp/include.php', 'scope' => '::file',
            'offset' => $parameters[$index]->getStartTokenPos(),
            'startOffset' => $parameters[$index]->getStartTokenPos(),
            'variable' => $name, 'sources' => ['laravel:route:' . $name],
            'requestProbability' => 95, 'unknown' => false, 'variables' => [],
        ];
    }

    expect($collector->processNode($call, $scope))->toBe([
        'kind' => 'extraAssignments', 'file' => '/tmp/include.php', 'scope' => '::file',
        'assignments' => $assignments,
    ]);
});

it('records complete events for array changes', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $scope->method('getType')->willReturn(new ArrayType(new MixedType(), new StringType()));
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(static fn (Node\Name $name): string => $name->toString());
    $collector = new Cwe98Collector($provider);
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php $alias = &$files; $files["x"] = $value; $files += $other; change($files); foreach ($files as $item) {}',
    );
    $base = ['kind' => 'assignment', 'file' => '/tmp/include.php', 'scope' => '::file'];
    $reference = $nodes[0]->expr;
    $referenceFacts = [
        'offset' => $reference->getEndTokenPos(), 'startOffset' => $reference->getStartTokenPos(),
    ];
    $referenceSource = ['sources' => [], 'requestProbability' => null, 'unknown' => true, 'variables' => ['files' => 95]];
    expect($collector->processNode($reference, $scope))->toBe([
        'kind' => 'extraAssignments', 'file' => '/tmp/include.php', 'scope' => '::file',
        'assignments' => [
            [...$base, ...$referenceFacts, 'variable' => 'files', ...$referenceSource],
            [...$base, ...$referenceFacts, 'variable' => 'alias', ...$referenceSource],
        ],
    ]);

    $element = $nodes[1]->expr;
    expect($collector->processNode($element, $scope))->toBe([
        ...$base, 'offset' => $element->getEndTokenPos(), 'startOffset' => $element->getStartTokenPos(),
        'variable' => 'files', 'sources' => [], 'requestProbability' => null,
        'unknown' => false, 'variables' => ['value' => 95, 'files' => 95],
    ]);
    $union = $nodes[2]->expr;
    expect($collector->processNode($union, $scope))->toBe([
        ...$base, 'offset' => $union->getEndTokenPos(), 'startOffset' => $union->getStartTokenPos(),
        'variable' => 'files', 'sources' => [], 'requestProbability' => null,
        'unknown' => false, 'variables' => ['other' => 95, 'files' => 95],
    ]);
    $call = $nodes[3]->expr;
    expect($collector->processNode($call, $scope))->toBe([
        'kind' => 'extraAssignments', 'file' => '/tmp/include.php', 'scope' => '::file',
        'assignments' => [[
            ...$base, 'offset' => $call->getEndTokenPos(), 'startOffset' => $call->getStartTokenPos(),
            'variable' => 'files', 'sources' => [], 'requestProbability' => null,
            'unknown' => true, 'variables' => ['files' => 85],
        ]],
    ]);
    $loop = $nodes[4];
    expect($collector->processNode($loop, $scope))->toBe([
        ...$base, 'offset' => $loop->valueVar->getEndTokenPos(), 'startOffset' => $loop->getStartTokenPos(),
        'variable' => 'item', 'sources' => [], 'requestProbability' => null,
        'unknown' => false, 'variables' => ['files' => 95],
    ]);
});

it('rejects unsupported array and foreach targets', function (string $code): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new ArrayType(new MixedType(), new StringType()));
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php ' . $code);
    $node = $nodes[0] instanceof Node\Stmt\Expression ? $nodes[0]->expr : $nodes[0];

    expect($collector->processNode($node, $scope))->toBeNull();
})->with([
    'foreach destructuring' => ['foreach ($files as [$item]) {}'],
    'reference property target' => ['$object->files = &$files;'],
    'reference property source' => ['$files = &$object->files;'],
    'array property root' => ['$object->files["item"] = "fixed";'],
    'dynamic array variable' => ['$$name["item"] = "fixed";'],
    'call with property' => ['change($object->files);'],
    'call with dynamic variable' => ['change($$name);'],
    'assignment to property' => ['$object->file .= "fixed";'],
]);

it('does not treat other named expressions as variables', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getType')->willReturn(new ArrayType(new MixedType(), new StringType()));
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $namedExpression = new Cwe98NamedExpression();
    $variable = new Expr\Variable('files');
    $nodes = [
        new Node\Stmt\Foreach_($namedExpression, new Expr\Variable('file'), ['byRef' => true]),
        new Expr\AssignRef($namedExpression, $variable),
        new Expr\AssignRef($variable, $namedExpression),
        new Expr\Assign(new Expr\ArrayDimFetch($namedExpression), new Node\Scalar\String_('fixed')),
        new Expr\FuncCall(new Node\Name('change'), [new Node\Arg($namedExpression)]),
    ];

    expect($collector->processNode($nodes[0], $scope)['kind'])->toBe('assignment');
    foreach (array_slice($nodes, 1) as $node) {
        expect($collector->processNode($node, $scope))->toBeNull();
    }
});

it('keeps reference loops over non-variable expressions separate', function (): void {
    $scope = $this->createStub(Scope::class);
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php foreach ($object->files as &$file) {}');
    $event = $collector->processNode($nodes[0], $scope);

    expect($event['kind'])->toBe('assignment')
        ->and($event['variable'])->toBe('file')
        ->and($event['unknown'])->toBeTrue();
});

it('does not collect unrelated nodes or unsupported assignment targets', function (): void {
    $scope = $this->createStub(Scope::class);
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php $object->file = "home.php"; $files["home"] = "home.php"; $$name = "home.php";',
    );

    expect($collector->processNode(new Node\Stmt\Nop(), $scope))->toBeNull()
        ->and($collector->processNode($nodes[0]->expr, $scope))->toBeNull()
        ->and($collector->processNode($nodes[1]->expr, $scope)['variables'])->toBe(['files' => 95])
        ->and($collector->processNode($nodes[2]->expr, $scope))->toBeNull();
});

it('adds the target dependency to a concatenation assignment', function (): void {
    $scope = $this->createStub(Scope::class);
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(static fn (Node\Name $name): string => $name->toString());
    $collector = new Cwe98Collector($provider);
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php $file .= $suffix; $file = $suffix; $file .= basename($file);');

    expect($collector->processNode($nodes[0]->expr, $scope)['variables'])->toBe(['suffix' => 95, 'file' => 95])
        ->and($collector->processNode($nodes[1]->expr, $scope)['variables'])->toBe(['suffix' => 95])
        ->and($collector->processNode($nodes[2]->expr, $scope)['variables'])->toBe(['file' => 95]);
});

it('propagates reflection failures instead of treating a call as safe', function (): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willThrowException(new RuntimeException('Cannot resolve function.'));
    $collector = new Cwe98Collector($provider);
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php include basename("home.php");');

    expect(fn () => $collector->processNode($nodes[0]->expr, $this->createStub(Scope::class)))
        ->toThrow(RuntimeException::class, 'Cannot resolve function.');
});

it('treats a function with an unresolved name as unknown', function (): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturn(null);
    $collector = new Cwe98Collector($provider);
    $nodes = (new ParserFactory())->createForHostVersion()->parse('<?php include basename("home.php");');
    $event = $collector->processNode($nodes[0]->expr, $this->createStub(Scope::class));

    expect($event['unknown'])->toBeTrue()
        ->and($event['sources'])->toBe([])
        ->and($event['variables'])->toBe([]);
});

it('keeps named class methods separate from file scope', function (): void {
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/include.php');
    $scope->method('getFunctionName')->willReturn('load');
    $scope->method('getClassReflection')->willReturn(
        $this->getContainer()->getByType(ReflectionProvider::class)->getClass(Cwe98Collector::class),
    );
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $event = $collector->processNode(new Expr\Include_(new Node\Scalar\String_('home.php'), Expr\Include_::TYPE_INCLUDE), $scope);

    expect($event['scope'])->toBe(Cwe98Collector::class . '::load');
});

it('ignores non-expression nodes and empty array items when collecting facts', function (): void {
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $scope = $this->createStub(Scope::class);

    expect(invade($collector)->expressionFacts(new Node\VariadicPlaceholder(), $scope))->toBe([
        'sources' => [],
        'requestProbability' => null,
        'unknown' => false,
        'variables' => [],
    ])->and(invade($collector)->expressionFacts(
        new Expr\Array_([null, new Node\ArrayItem(new Expr\Variable('page'))]),
        $scope,
    ))->toBe([
        'sources' => [],
        'requestProbability' => null,
        'unknown' => false,
        'variables' => ['page' => 95],
    ]);
});
