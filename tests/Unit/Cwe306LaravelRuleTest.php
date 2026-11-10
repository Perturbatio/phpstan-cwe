<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe306\Cwe306LaravelRule;
use Perturbatio\PhpstanCwe\Rules\Cwe306\LaravelAuthenticationScanner;
use PhpParser\ParserFactory;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Parser\Parser;

covers(Cwe306LaravelRule::class, LaravelAuthenticationScanner::class);

it('reports an empty critical operation list once regardless of files or probability', function (int $minimum, bool $hasFiles): void {
    $parser = $this->createMock(Parser::class);
    $parser->expects($this->never())->method('parseFile');
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(), $minimum);
    $files = $hasFiles ? [
        __DIR__ . '/../fixtures/CWE-306/laravel.php' => [AnalysedFileCollector::class => [true]],
        __DIR__ . '/../fixtures/CWE-306/controller.php' => [AnalysedFileCollector::class => [true]],
    ] : [];
    $reports = $rule->processNode(new CollectedDataNode($files, false), $this->createStub(Scope::class));

    expect($reports)->toHaveCount(1)
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.cwe306Configuration')
        ->and($reports[0]->getMessage())->toBe('CWE-306 is enabled, but no critical operations are configured. Set phpstanCwe.cwe306CriticalOperations to the functions or methods that require authentication.');
})->with([[0, false], [0, true], [100, false], [100, true]]);

it('does not report a configuration problem when an operation is configured', function (): void {
    $rule = new Cwe306LaravelRule($this->createStub(Parser::class), new LaravelAuthenticationScanner(['eraseAccounts']), 100);
    expect($rule->processNode(new CollectedDataNode([], false), $this->createStub(Scope::class)))->toBe([]);
});

it('makes ignorable CWE-306 reports and applies the probability minimum', function (int $minimum, int $count): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(
        "<?php\nuse Illuminate\Support\Facades\Route;\nRoute::post('/erase', function () { eraseAccounts(); });",
    );
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn($nodes);
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), $minimum);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $data = new CollectedDataNode([$file => [AnalysedFileCollector::class => [true]]], false);
    $reports = $rule->processNode($data, $this->createStub(Scope::class));

    expect($rule->getNodeType())->toBe(CollectedDataNode::class)
        ->and($reports)->toHaveCount($count);
    if ($count === 0) {
        return;
    }
    expect($reports[0]->getMessage())->toBe('CWE-306: A Laravel route reaches critical operation eraseAccounts without a supported authentication control. Severity: high. Probability: 60%. https://cwe.mitre.org/data/definitions/306.html')
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.cwe306')
        ->and($reports[0]->getFile())->toBe($file)
        ->and($reports[0]->getLine())->toBe(3)
        ->and($reports[0]->getMetadata())->toBe([
            'cwe' => 306,
            'severity' => 'high',
            'probability' => 60,
            'url' => 'https://cwe.mitre.org/data/definitions/306.html',
        ])
        ->and($reports[0])->not->toBeInstanceOf(PHPStan\Rules\NonIgnorableRuleError::class)
        ->and($reports[0]->getTip())->toContain('Unknown middleware');
})->with([[0, 1], [60, 1], [61, 0]]);

it('rejects invalid CWE-306 probability limits', function (int $minimum): void {
    expect(fn () => new Cwe306LaravelRule(
        $this->createStub(Parser::class),
        new LaravelAuthenticationScanner(),
        $minimum,
    ))->toThrow(InvalidArgumentException::class);
})->with([-1, 101]);

it('uses a zero minimum when no probability is supplied', function (): void {
    $rule = new Cwe306LaravelRule($this->createStub(Parser::class), new LaravelAuthenticationScanner());
    $minimum = new ReflectionProperty($rule, 'minProbability');

    expect($minimum->getValue($rule))->toBe(0);
});

it('checks ignore reasons even when all findings are below the minimum', function (): void {
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn(
        (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
use Illuminate\Support\Facades\Route;
// @phpstan-ignore phpstanCwe.cwe306 (safe)
Route::post('/erase', function () { eraseAccounts(); });
PHP),
    );
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), 100);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $data = new CollectedDataNode([$file => [AnalysedFileCollector::class => [true]]], false);
    $reports = $rule->processNode($data, $this->createStub(Scope::class));

    expect($reports)->toHaveCount(1)
        ->and($reports[0]->getMessage())->toBe('CWE-306 ignore requires a reason with at least two words.')
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.ignoreReason')
        ->and($reports[0]->getLine())->toBe(3)
        ->and($reports[0]->getFile())->toBe($file);
});

it('keeps a stronger finding after filtering a weaker finding', function (): void {
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn(
        (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
use Illuminate\Support\Facades\Route;
Route::post('/unknown', function () { unknownControl(); eraseAccounts(); });
Route::post('/known', function () { eraseAccounts(); });
PHP),
    );
    $rule = new Cwe306LaravelRule($parser, new LaravelAuthenticationScanner(['eraseAccounts']), 60);
    $file = __DIR__ . '/../fixtures/CWE-306/laravel.php';
    $data = new CollectedDataNode([$file => [AnalysedFileCollector::class => [true]]], false);
    $reports = $rule->processNode($data, $this->createStub(Scope::class));

    expect($reports)->toHaveCount(1)
        ->and($reports[0]->getLine())->toBe(4)
        ->and($reports[0]->getMetadata()['probability'])->toBe(60);
});
