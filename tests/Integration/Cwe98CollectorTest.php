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

uses(PHPStanTestCase::class);

covers(Cwe98Collector::class);

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

it('does not collect unrelated nodes or unsupported assignment targets', function (): void {
    $scope = $this->createStub(Scope::class);
    $collector = new Cwe98Collector($this->createStub(ReflectionProvider::class));
    $nodes = (new ParserFactory())->createForHostVersion()->parse(
        '<?php $object->file = "home.php"; $files["home"] = "home.php"; $$name = "home.php";',
    );

    expect($collector->processNode(new Node\Stmt\Nop(), $scope))->toBeNull()
        ->and($collector->processNode($nodes[0]->expr, $scope))->toBeNull()
        ->and($collector->processNode($nodes[1]->expr, $scope))->toBeNull()
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
