<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;
use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use Perturbatio\PhpstanCwe\Rules\Cwe306\Cwe306LaravelRule;
use Perturbatio\PhpstanCwe\Rules\Cwe306\LaravelAuthenticationScanner;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79BladeRule;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe95\Cwe95Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89Rule;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Parser\Parser;

covers(Cwe95Rule::class, Cwe78Rule::class, Cwe79Rule::class, Cwe89Rule::class, Cwe79BladeRule::class, Cwe306LaravelRule::class, BladeTemplateScanner::class, LaravelAuthenticationScanner::class);

function ignoreEventFor(int $cwe, string $file, string $fingerprint, array $changes = []): array
{
    return array_replace([
        'cwe' => $cwe,
        'file' => $file,
        'line' => 2,
        'startOffset' => 10,
        'endOffset' => 30,
        'startLine' => 3,
        'endLine' => 3,
        'fingerprint' => $fingerprint,
        'reason' => 'checked input',
    ], $changes);
}

function ruleIdentifiers(array $errors): array
{
    return array_map(static fn ($error): ?string => $error->getIdentifier(), $errors);
}

it('suppresses a CWE-78 finding with a package ignore and reports an ignore in a file without events', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-78/cwe78.php';
    $other = __DIR__ . '/../fixtures/CWE-78/ignore.php';
    $fingerprint = CweFingerprint::make(78, [$file, 'S', 'shell_exec($c)', '000']);
    $sink = ['kind' => 'sink', 'file' => $file, 'scope' => 'S', 'expression' => 'shell_exec($c)', 'offset' => 20, 'line' => 4, 'request' => false, 'hasStaticText' => false, 'throughAssignment' => false, 'variables' => []];
    $node = new CollectedDataNode([
        $file => [
            Cwe78Collector::class => [$sink, $sink],
            CweIgnoreCollector::class => [[ignoreEventFor(78, $file, $fingerprint)]],
        ],
        $other => [CweIgnoreCollector::class => [[ignoreEventFor(78, $other, $fingerprint)]]],
    ], false);

    $errors = (new Cwe78Rule())->processNode($node, $this->createStub(Scope::class));

    expect(ruleIdentifiers($errors))->toBe(['phpstanCwe.cwe78', 'phpstanCwe.ignoreUnmatched'])
        ->and($errors[0]->getFile())->toBe($file)
        ->and($errors[1]->getFile())->toBe($other);
});

it('suppresses a CWE-79 finding with a package ignore and reports an ignore in a file without events', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-79/cwe79.php';
    $other = __DIR__ . '/../fixtures/CWE-79/assignments.php';
    $fingerprint = CweFingerprint::make(79, [$file, 'file', '$_GET["a"]']);
    $sink = ['kind' => 'sink', 'scope' => 'file', 'offset' => 20, 'line' => 5, 'request' => true, 'variables' => [], 'expression' => '$_GET["a"]'];
    $node = new CollectedDataNode([
        $file => [
            Cwe79Collector::class => [$sink, $sink],
            CweIgnoreCollector::class => [[ignoreEventFor(79, $file, $fingerprint)]],
        ],
        $other => [CweIgnoreCollector::class => [[ignoreEventFor(79, $other, $fingerprint)]]],
    ], false);

    $errors = (new Cwe79Rule())->processNode($node, $this->createStub(Scope::class));

    expect(ruleIdentifiers($errors))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.ignoreUnmatched'])
        ->and($errors[0]->getFile())->toBe($file)
        ->and($errors[1]->getFile())->toBe($other);
});

it('skips null direct events and suppresses direct and Laravel CWE-89 findings with their own ignores', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-89/cwe89.php';
    $other = __DIR__ . '/../fixtures/CWE-89/laravel.php';
    $direct = ['file' => $file, 'scope' => 'S', 'offset' => 20, 'line' => 5, 'expression' => 'q: $_GET["a"]'];
    $fingerprint = CweFingerprint::make(89, [$file, 'S', 'direct', 'q: $_GET["a"]']);
    $node = new CollectedDataNode([
        $file => [
            Cwe89Collector::class => [null, $direct, $direct],
            CweIgnoreCollector::class => [[ignoreEventFor(89, $file, $fingerprint)]],
        ],
        $other => [CweIgnoreCollector::class => [[ignoreEventFor(89, $other, $fingerprint)]]],
    ], false);

    $errors = (new Cwe89Rule())->processNode($node, $this->createStub(Scope::class));

    expect(ruleIdentifiers($errors))->toBe(['phpstanCwe.cwe89', 'phpstanCwe.ignoreUnmatched'])
        ->and($errors[0]->getLine())->toBe(5)
        ->and($errors[1]->getFile())->toBe($other);
});

it('suppresses a CWE-306 route finding with a package ignore', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        "<?php\nuse Illuminate\Support\Facades\Route;\nRoute::post('/erase', function () { eraseAccounts(); });",
    );
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn($nodes);
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), 0);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $data = static fn (array $ignores): CollectedDataNode => new CollectedDataNode([$file => [
        AnalysedFileCollector::class => [true],
        CweIgnoreCollector::class => [$ignores],
    ]], false);
    $first = $rule->processNode($data([]), $this->createStub(Scope::class));
    $fingerprint = $first[0]->getMetadata()['fingerprint'];

    $suppressed = $rule->processNode($data([ignoreEventFor(306, $file, $fingerprint, ['startLine' => 3, 'endLine' => 3])]), $this->createStub(Scope::class));
    $stale = $rule->processNode($data([ignoreEventFor(306, $file, str_repeat('0', 64), ['startLine' => 3, 'endLine' => 3])]), $this->createStub(Scope::class));

    expect($first)->toHaveCount(1)
        ->and($suppressed)->toBe([])
        ->and(ruleIdentifiers($stale))->toBe(['phpstanCwe.cwe306', 'phpstanCwe.ignoreUnmatched']);
});

it('matches Blade package ignores with the raw echo that follows them', function (): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/view.blade.php';
    $scanner = new BladeTemplateScanner();
    $rule = new Cwe79BladeRule($scanner, [$directory]);
    $node = new CollectedDataNode(['index.php' => [AnalysedFileCollector::class => [true]]], false);
    $run = function (string $view) use ($file, $rule, $node): array {
        file_put_contents($file, $view);

        return $rule->processNode($node, $this->createStub(Scope::class));
    };

    try {
        $hash = CweFingerprint::make(79, [$file, 'blade', '$value']);
        $valid = "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked value) --}}\n{!! \$value !!}\n{!! \$value !!}";
        $sameLine = "{{-- @phpstan-ignore phpstanCwe.cwe79." . strtoupper($hash) . " (checked value) --}} {!!   \$value   !!}";
        $tooFar = "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked value) --}}\n\n{!! \$value !!}";
        $notEcho = "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked value) --}} text {!! \$value !!}";
        $short = "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked) --}}\n{!! \$value !!}";
        $bare = "{{-- @phpstan-ignore phpstanCwe.cwe79 --}}\n{!! \$value !!}";
        $escaped = "@{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked value) --}}\n{!! \$value !!}";
        $native = "{{-- @phpstan-ignore phpstanCwe.cwe79 (Checked value) --}}\n{!! \$value !!}";

        expect(ruleIdentifiers($run($valid)))->toBe(['phpstanCwe.cwe79'])
            ->and($run($valid)[0]->getLine())->toBe(3)
            ->and($run($sameLine))->toBe([])
            ->and(ruleIdentifiers($run($tooFar)))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.ignoreUnmatched'])
            ->and(ruleIdentifiers($run($notEcho)))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.ignoreUnmatched'])
            ->and(ruleIdentifiers($run($short)))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.ignoreReason'])
            ->and(ruleIdentifiers($run($bare)))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.ignoreFingerprint', 'phpstanCwe.ignoreReason'])
            ->and(ruleIdentifiers($run($escaped)))->toBe(['phpstanCwe.cwe79'])
            ->and(ruleIdentifiers($run($native)))->toBe(['phpstanCwe.cwe79','phpstanCwe.ignoreFingerprint']);

        $reports = $run($bare);
        $reasonReport = $reports[2];
        expect($reports[1]->getMessage())->toBe('CWE-79 ignore must include a 64-character fingerprint.')
            ->and($reasonReport->getMessage())->toBe('CWE-79 ignore requires a reason with at least two words.')
            ->and($reports[0]->getTip())->toContain('phpstanCwe.cwe79.');

        $mixed = "{{-- @phpstan-ignore phpstanCwe.cwe79 --}} text\n{{-- @phpstan-ignore phpstanCwe.cwe79 --}} text"; // native comment is plain text
        expect(ruleIdentifiers($run($mixed)))->toBe(['phpstanCwe.ignoreFingerprint', 'phpstanCwe.ignoreReason', 'phpstanCwe.ignoreFingerprint','phpstanCwe.ignoreReason']);
    } finally {
        unlink($file);
        rmdir($directory);
    }
});

function staleIgnoreMessage(int $cwe): string
{
    return sprintf('CWE-%d ignore fingerprint does not match a finding. Review or remove this ignore.', $cwe);
}

it('gives each rule its own CWE number in tips, fingerprints, and ignore reports', function (): void {
    $scope = $this->createStub(Scope::class);
    $stale = str_repeat('0', 64);

    $file78 = __DIR__ . '/../fixtures/CWE-78/cwe78.php';
    $sink78 = ['kind' => 'sink', 'file' => $file78, 'scope' => 'S', 'expression' => 'shell_exec($c)', 'offset' => 20, 'line' => 4, 'request' => false, 'hasStaticText' => false, 'throughAssignment' => false, 'variables' => []];
    $errors78 = (new Cwe78Rule())->processNode(new CollectedDataNode([$file78 => [
        Cwe78Collector::class => [$sink78],
        CweIgnoreCollector::class => [[ignoreEventFor(78, $file78, $stale)]],
    ]], false), $scope);
    $fingerprint78 = CweFingerprint::make(78, [$file78, 'S', 'shell_exec($c)', '000']);

    $file79 = __DIR__ . '/../fixtures/CWE-79/cwe79.php';
    $sink79 = ['kind' => 'sink', 'scope' => 'S', 'offset' => 20, 'line' => 5, 'request' => true, 'variables' => [], 'expression' => '$_GET["a"]'];
    $errors79 = (new Cwe79Rule())->processNode(new CollectedDataNode([$file79 => [
        Cwe79Collector::class => [$sink79],
        CweIgnoreCollector::class => [[ignoreEventFor(79, $file79, $stale)]],
    ]], false), $scope);
    $fingerprint79 = CweFingerprint::make(79, [$file79, 'S', '$_GET["a"]']);

    $file89 = __DIR__ . '/../fixtures/CWE-89/cwe89.php';
    $direct = ['file' => $file89, 'scope' => 'S', 'offset' => 20, 'line' => 5, 'expression' => 'q: $_GET["a"]'];
    $laravel = ['kind' => 'sink', 'file' => $file89, 'scope' => 'S', 'offset' => 40, 'line' => 6, 'dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => [], 'expression' => 'where: $q'];
    $errors89 = (new Cwe89Rule())->processNode(new CollectedDataNode([$file89 => [
        Cwe89Collector::class => [$direct],
        Cwe89LaravelCollector::class => [$laravel],
        CweIgnoreCollector::class => [[ignoreEventFor(89, $file89, $stale)]],
    ]], false), $scope);
    $fingerprint89Direct = CweFingerprint::make(89, [$file89, 'S', 'direct', 'q: $_GET["a"]']);
    $fingerprint89Laravel = CweFingerprint::make(89, [$file89, 'S', 'laravel', 'where: $q', '2']);

    expect($errors78[0]->getMetadata()['fingerprint'])->toBe($fingerprint78)
        ->and($errors78[0]->getTip())->toBe(CweIgnoreSet::tip(78, $fingerprint78, 'the command and its arguments'))
        ->and($errors78[1]->getMessage())->toBe(staleIgnoreMessage(78))
        ->and($errors79[0]->getMetadata()['fingerprint'])->toBe($fingerprint79)
        ->and($errors79[0]->getTip())->toBe(CweIgnoreSet::tip(79, $fingerprint79, 'the printed value'))
        ->and($errors79[1]->getMessage())->toBe(staleIgnoreMessage(79))
        ->and($errors89[0]->getMetadata()['fingerprint'])->toBe($fingerprint89Direct)
        ->and($errors89[0]->getTip())->toBe(CweIgnoreSet::tip(89, $fingerprint89Direct, 'the SQL text'))
        ->and($errors89[1]->getMetadata()['fingerprint'])->toBe($fingerprint89Laravel)
        ->and($errors89[1]->getTip())->toEndWith("\n" . CweIgnoreSet::tip(89, $fingerprint89Laravel, 'the SQL text'))
        ->and($errors89[1]->getTip())->toStartWith('If you use wrap()')
        ->and($errors89[2]->getMessage())->toBe(staleIgnoreMessage(89));
});

it('gives CWE-306 its own number in the tip, fingerprint, and ignore reports', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        "<?php\nuse Illuminate\Support\Facades\Route;\nRoute::post('/erase', function () { eraseAccounts(); });",
    );
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn($nodes);
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), 0);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $errors = $rule->processNode(new CollectedDataNode([
        $file => [AnalysedFileCollector::class => [true], CweIgnoreCollector::class => [[ignoreEventFor(306, $file, str_repeat('0', 64))]]],
    ], false), $this->createStub(Scope::class));
    $fingerprint = CweFingerprint::make(306, [$file, "post('/erase') -> closure", 'eraseAccounts']);

    expect($errors)->toHaveCount(2)
        ->and($errors[0]->getMetadata()['fingerprint'])->toBe($fingerprint)
        ->and($errors[0]->getTip())->toBe("Require authentication before this operation. Unknown middleware and calls can contain controls that this rule cannot resolve.\n" . CweIgnoreSet::tip(306, $fingerprint, 'this route and operation'))
        ->and($errors[1]->getMessage())->toBe(staleIgnoreMessage(306));
});

it('sorts CWE-95 sources in the fingerprint and reports ignores after files with findings', function (): void {
    $first = __DIR__ . '/../fixtures/CWE-95/cwe95.php';
    $second = __DIR__ . '/../fixtures/CWE-95/stale-ignore.php';
    $event = ['kind' => 'sink', 'file' => $first, 'scope' => 'S', 'offset' => 20, 'startOffset' => 20, 'line' => 4, 'expression' => 'eval($c)', 'sources' => ['b', 'a'], 'unknown' => false, 'variables' => []];
    $expected = CweFingerprint::make(95, [$first, 'S', 'eval($c)', 'a|b']);
    $errors = (new Cwe95Rule())->processNode(new CollectedDataNode([
        $first => [Cwe95Collector::class => [$event], CweIgnoreCollector::class => [[ignoreEventFor(95, $first, $expected)]]],
        $second => [CweIgnoreCollector::class => [[ignoreEventFor(95, $second, $expected)]]],
    ], false), $this->createStub(Scope::class));

    expect(ruleIdentifiers($errors))->toBe(['phpstanCwe.ignoreUnmatched'])
        ->and($errors[0]->getFile())->toBe($second);
});

it('keeps the CWE-306 route identity lower case', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        "<?php\nuse Illuminate\Support\Facades\Route;\nRoute::POST('/erase', function () { eraseAccounts(); });",
    );
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn($nodes);
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), 0);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $errors = $rule->processNode(new CollectedDataNode([
        $file => [AnalysedFileCollector::class => [true]],
    ], false), $this->createStub(Scope::class));

    expect($errors[0]->getMetadata()['fingerprint'])
        ->toBe(CweFingerprint::make(306, [$file, "post('/erase') -> closure", 'eraseAccounts']));
});

it('accepts a numeric file key for CWE-89 ignores', function (): void {
    $errors = (new Cwe89Rule())->processNode(new CollectedDataNode([
        '123' => [Cwe89Collector::class => [null]],
    ], false), $this->createStub(Scope::class));

    expect($errors)->toBe([]);
});
