<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;
use Perturbatio\PhpstanCwe\Rules\Cwe79BladeRule;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;

covers(Cwe79BladeRule::class);

function bladeRuleNode(bool $hasAnalysedFiles): CollectedDataNode
{
    $collectedData = $hasAnalysedFiles
        ? ['index.php' => [AnalysedFileCollector::class => [true]]]
        : [];

    return new CollectedDataNode($collectedData, false);
}

it('reports raw echoes and unmatched ignore comments from analysed files', function (): void {
    $directories = [
        __DIR__ . '/../fixtures/CWE-79/blade/ignores',
        __DIR__ . '/../fixtures/CWE-79/blade/views',
    ];
    $rule = new Cwe79BladeRule(new BladeTemplateScanner(), $directories);

    $errors = $rule->processNode(bladeRuleNode(true), $this->createStub(Scope::class));
    $identifiers = array_map(
        static fn (IdentifierRuleError $error): ?string => $error->getIdentifier(),
        $errors,
    );

    expect($rule->getNodeType())->toBe(CollectedDataNode::class)
        ->and(invade($rule)->minProbability)->toBe(0)
        ->and($identifiers)->toHaveCount(18)
        ->and($errors[0]->getMessage())->toBe('CWE-79: A Blade raw echo prints a value without HTML escape. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html')
        ->and($identifiers)->toContain('phpstanCwe.cwe79', 'phpstanCwe.ignoreUnmatched')
        ->and(Cwe79BladeRule::getProbability())->toBe(80)
        ->and(Cwe79BladeRule::getIgnoreTip())->toBe(
            'Only if you are sure that this value is safe HTML, put {{-- @phpstan-ignore phpstanCwe.cwe79 (Reason) --}} immediately BEFORE this raw echo. Replace "Reason" with the reason.',
        );
});

it('reports raw echoes after unmatched ignores with the correct report data', function (): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/view.blade.php';
    file_put_contents($file, "{{-- @phpstan-ignore phpstanCwe.cwe79 --}}\n\n{!! \$value !!}");
    try {
        $rule = new Cwe79BladeRule(new BladeTemplateScanner(), [$directory], 80);
        $errors = $rule->processNode(bladeRuleNode(true), $this->createStub(Scope::class));
        expect($errors)->toHaveCount(2)
            ->and($errors[0]->getIdentifier())->toBe('phpstanCwe.cwe79')
            ->and($errors[0]->getLine())->toBe(3)
            ->and($errors[0]->getFile())->toBe($file)
            ->and($errors[1]->getIdentifier())->toBe('phpstanCwe.ignoreUnmatched')
            ->and($errors[1]->getLine())->toBe(1)
            ->and($errors[1]->getFile())->toBe($file)
            ->and($errors[1]->getMessage())->toBe('No Blade raw echo matches @phpstan-ignore phpstanCwe.cwe79.');
    } finally {
        unlink($file);
        rmdir($directory);
    }
});

it('skips scans without analysed files and below the probability minimum', function (): void {
    $invalidDirectory = __DIR__ . '/../fixtures/CWE-79/missing';
    $scope = $this->createStub(Scope::class);
    $enabledRule = new Cwe79BladeRule(new BladeTemplateScanner(), [$invalidDirectory]);
    $disabledRule = new Cwe79BladeRule(new BladeTemplateScanner(), [$invalidDirectory], 81);

    expect($enabledRule->processNode(bladeRuleNode(false), $scope))->toBe([])
        ->and($disabledRule->processNode(bladeRuleNode(true), $scope))->toBe([]);
});

it('rejects a probability minimum outside the valid range', function (): void {
    expect(fn () => new Cwe79BladeRule(new BladeTemplateScanner(), [], 101))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => new Cwe79BladeRule(new BladeTemplateScanner(), [], -1))
        ->toThrow(InvalidArgumentException::class);
});
