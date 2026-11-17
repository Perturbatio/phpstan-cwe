<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95IgnoreCollector;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Testing\PHPStanTestCase;
use PHPStan\Type\MixedType;
use PHPStan\Type\ObjectType;

uses(PHPStanTestCase::class);

covers(Cwe95Collector::class, Cwe95IgnoreCollector::class);

it('collects eval expression facts without treating transformations as protection', function (
    string $expression,
    array $sources,
    bool $unknown,
    array $variables,
    bool $checkLaravelInput = false,
): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturnCallback(
        static fn (Node\Name $name): string => $name->toString(),
    );
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/eval.php');
    $scope->method('getType')->willReturnCallback(
        static fn (Expr $node) => $node instanceof Expr\Variable && $node->name === 'request'
            ? new ObjectType('Illuminate\Http\Request')
            : new MixedType(),
    );
    $collector = new Cwe95Collector($provider, $checkLaravelInput);
    $statements = (new ParserFactory())->createForHostVersion()->parse("<?php\neval({$expression});");
    $sink = $statements[0]->expr;
    $event = $collector->processNode($sink, $scope);

    expect($collector->getNodeType())->toBe(Node::class)
        ->and($event)->toBe([
            'kind' => 'sink',
            'file' => '/tmp/eval.php',
            'scope' => '::file',
            'offset' => $sink->getStartTokenPos(),
            'line' => 2,
            'expression' => (new PhpParser\PrettyPrinter\Standard())->prettyPrintExpr($sink),
            'sources' => $sources,
            'unknown' => $unknown,
            'variables' => $variables,
        ]);
})->with([
    'nested PHP input' => ['$_REQUEST["payload"]["code"]', ['php:$_REQUEST["payload"]["code"]'], false, []],
    'whole superglobal' => ['$_GET', ['php:$_GET'], false, []],
    'local value' => ['$code', [], false, ['code']],
    'variable variable' => ['$$name', [], true, []],
    'fixed text' => ["'return 1;'", [], false, []],
    'numeric value' => ['123', [], false, []],
    'local array' => ['$values["code"]', [], false, ['values']],
    'call arguments' => ['transform($_POST["code"], $prefix)', ['php:$_POST["code"]'], true, ['prefix']],
    'array items' => ['["code" => $_COOKIE["code"], null]', ['php:$_COOKIE["code"]'], false, []],
    'property' => ['$object->code', [], true, ['object']],
    'nullsafe property' => ['$object?->code', [], true, ['object']],
    'repeated dependencies' => ['$code . $code', [], false, ['code']],
    'helper disabled' => ['request("code")', [], true, []],
    'helper enabled' => ['request("code")', ['laravel:request("code")'], false, [], true],
    'request method' => ['$request->input("code")', ['laravel:$request->input("code")'], false, [], true],
    'unrelated method' => ['$object->input("code")', [], true, ['object'], true],
    'escape is not protection' => ['htmlspecialchars($_GET["code"])', ['php:$_GET["code"]'], true, []],
    'duplicate sources' => ['$_GET["a"] . $_GET["a"] . $_POST["b"]', ['php:$_GET["a"]', 'php:$_POST["b"]'], false, []],
    'overlapping source groups' => [
        '($_GET["a"] . $_POST["b"]) . ($_GET["a"] . $_COOKIE["c"])',
        ['php:$_GET["a"]', 'php:$_POST["b"]', 'php:$_COOKIE["c"]'], false, [],
    ],
    'overlapping variable groups' => ['($first . $second) . ($first . $third)', [], false, ['first', 'second', 'third']],
    'unknown on left' => ['unknown() . "fixed"', [], true, []],
    'unknown on right' => ['"fixed" . unknown()', [], true, []],
    'multiple local values' => ['$first . $first . $second', [], false, ['first', 'second']],
    'constant text' => ['true', [], false, []],
    'array from a call' => ['getValues()["code"]', [], true, []],
]);

it('merges nullable array items and non-expression nodes without unknown input', function (): void {
    $collector = new Cwe95Collector($this->createStub(ReflectionProvider::class));
    $scope = $this->createStub(Scope::class);
    $facts = invade($collector)->expressionFacts(
        new Expr\Array_([null, new Node\ArrayItem(new Expr\Variable('code'))]),
        $scope,
    );
    expect($facts)->toBe(['sources' => [], 'unknown' => false, 'variables' => ['code']])
        ->and(invade($collector)->expressionFacts(new Node\VariadicPlaceholder(), $scope))
        ->toBe(['sources' => [], 'unknown' => false, 'variables' => []]);
});

it('defaults to PHP-only input detection', function (): void {
    $provider = $this->createStub(ReflectionProvider::class);
    $provider->method('resolveFunctionName')->willReturn('request');
    $collector = new Cwe95Collector($provider);
    $event = $collector->processNode(
        new Expr\Eval_(new Expr\FuncCall(new Node\Name('request'), [new Node\Arg(new Node\Scalar\String_('code'))])),
        $this->createStub(Scope::class),
    );

    expect($event['sources'])->toBe([])
        ->and($event['unknown'])->toBeTrue();
});

it('keeps named class methods separate in collected events', function (): void {
    $scope = $this->createStub(Scope::class);
    $function = $this->createStub(PHPStan\Reflection\Php\PhpFunctionFromParserNodeReflection::class);
    $function->method('getName')->willReturn('evaluate');
    $class = $this->getContainer()->getByType(ReflectionProvider::class)->getClass(Cwe95Collector::class);
    $scope->method('getFunction')->willReturn($function);
    $scope->method('getClassReflection')->willReturn($class);
    $event = (new Cwe95Collector($this->createStub(ReflectionProvider::class)))
        ->processNode(new Expr\Eval_(new Node\Scalar\String_('return 1;')), $scope);

    expect($event['scope'])->toBe(Cwe95Collector::class . '::evaluate');
});

it('checks every supported PHP request root and its default list', function (): void {
    expect((new ReflectionClass(Cwe95Collector::class))->getConstant('REQUEST_VARIABLES'))
        ->toBe(['_GET', '_POST', '_COOKIE', '_REQUEST']);
});

it('records concatenation dependencies and rejects unsupported assignment targets', function (): void {
    $collector = new Cwe95Collector($this->createStub(ReflectionProvider::class));
    $scope = $this->createStub(Scope::class);
    $statements = (new ParserFactory())->createForHostVersion()->parse('<?php $code .= $code . $_GET["code"]; $object->code = "text"; $$name = "text";');
    $event = $collector->processNode($statements[0]->expr, $scope);

    expect($event['kind'])->toBe('assignment')
        ->and($event['variable'])->toBe('code')
        ->and($event['variables'])->toBe(['code'])
        ->and($event['sources'])->toBe(['php:$_GET["code"]'])
        ->and($event['unknown'])->toBeFalse()
        ->and($collector->processNode($statements[1]->expr, $scope))->toBeNull()
        ->and($collector->processNode($statements[2]->expr, $scope))->toBeNull()
        ->and($collector->processNode(new Node\Stmt\Nop(), $scope))->toBeNull();
});

it('marks an unresolved expression as unknown', function (): void {
    $collector = new Cwe95Collector($this->createStub(ReflectionProvider::class));
    $event = $collector->processNode(
        new Expr\Assign(new Expr\Variable('code'), new Expr\Error()),
        $this->createStub(Scope::class),
    );

    expect($event['unknown'])->toBeTrue()
        ->and($event['sources'])->toBe([])
        ->and($event['variables'])->toBe([]);
});

it('ignores nodes and comments without a package ignore directive', function (): void {
    $collector = new Cwe95IgnoreCollector();
    $scope = $this->createStub(Scope::class);
    $statement = new Node\Stmt\Nop(['comments' => [new PhpParser\Comment('// Review this code.')]]);

    expect($collector->getNodeType())->toBe(Node::class)
        ->and($collector->processNode(new Expr\Variable('code'), $scope))->toBeNull()
        ->and($collector->processNode(new Node\Stmt\Nop(), $scope))->toBeNull()
        ->and($collector->processNode($statement, $scope))->toBeNull();
});

it('collects invalid fingerprints and normalises valid fingerprints', function (string $annotation, string $fingerprint, string $reason): void {
    $collector = new Cwe95IgnoreCollector();
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/eval.php');
    $statement = new Node\Stmt\Nop([
        'startTokenPos' => 20,
        'endTokenPos' => 21,
        'comments' => [new PhpParser\Comment('// Review this code.', 2), new PhpParser\Comment($annotation, 3)],
    ]);

    expect($collector->processNode($statement, $scope))->toBe([
        'file' => '/tmp/eval.php',
        'line' => 3,
        'startOffset' => 20,
        'endOffset' => 21,
        'fingerprint' => $fingerprint,
        'reason' => $reason,
    ]);
})->with([
    'invalid hash' => ['// @phpstan-cwe-ignore phpstanCwe.cwe95[invalid] (Reviewed code)', '', 'Reviewed code'],
    'uppercase hash' => ['// @phpstan-cwe-ignore phpstanCwe.cwe95[' . str_repeat('A', 64) . '] ( Reviewed code )', str_repeat('a', 64), 'Reviewed code'],
]);

it('does not collect ignore directives from expression nodes', function (): void {
    $expression = new Expr\Variable('code', [
        'comments' => [new PhpParser\Comment('// @phpstan-cwe-ignore phpstanCwe.cwe95[invalid] (Reviewed code)')],
    ]);

    expect((new Cwe95IgnoreCollector())->processNode($expression, $this->createStub(Scope::class)))->toBeNull();
});

it('keeps assignment offsets and dependency lists exact', function (bool $concatenate): void {
    $expression = new Expr\BinaryOp\Concat(new Expr\Variable('first'), new Expr\Variable('first'));
    $node = $concatenate
        ? new Expr\AssignOp\Concat(new Expr\Variable('code'), $expression, ['startTokenPos' => 5, 'endTokenPos' => 15])
        : new Expr\Assign(new Expr\Variable('code'), $expression, ['startTokenPos' => 5, 'endTokenPos' => 15]);
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('/tmp/eval.php');
    $event = (new Cwe95Collector($this->createStub(ReflectionProvider::class)))->processNode($node, $scope);

    expect($event)->toBe([
        'kind' => 'assignment',
        'file' => '/tmp/eval.php',
        'scope' => '::file',
        'offset' => 15,
        'startOffset' => 5,
        'variable' => 'code',
        'sources' => [],
        'unknown' => false,
        'variables' => $concatenate ? ['first', 'code'] : ['first'],
    ]);
})->with([false, true]);

it('does not collect assignments to array elements', function (): void {
    $node = new Expr\Assign(new Expr\ArrayDimFetch(new Expr\Variable('codes'), new Node\Scalar\String_('code')), new Node\Scalar\String_('text'));
    expect((new Cwe95Collector($this->createStub(ReflectionProvider::class)))->processNode($node, $this->createStub(Scope::class)))->toBeNull();
});
