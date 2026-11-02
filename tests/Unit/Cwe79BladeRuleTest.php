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
        __DIR__ . '/../fixtures/CWE-79/blade/views',
        __DIR__ . '/../fixtures/CWE-79/blade/ignores',
    ];
    $rule = new Cwe79BladeRule(new BladeTemplateScanner(), $directories);

    $errors = $rule->processNode(bladeRuleNode(true), $this->createStub(Scope::class));
    $identifiers = array_map(
        static fn (IdentifierRuleError $error): ?string => $error->getIdentifier(),
        $errors,
    );
    $errorCounts = array_count_values($identifiers);

    expect($rule->getNodeType())->toBe(CollectedDataNode::class)
        ->and($identifiers)->toContain('phpstanCwe.cwe79', 'phpstanCwe.ignoreUnmatched')
        ->and($errorCounts['phpstanCwe.cwe79'])->toBe(14)
        ->and($errorCounts['phpstanCwe.ignoreUnmatched'])->toBe(4)
        ->and(invade($rule)->minProbability)->toBe(0)
        ->and(Cwe79BladeRule::getProbability())->toBe(80)
        ->and(Cwe79BladeRule::getIgnoreTip())->toBe(
            'Only if you are sure that this value is safe HTML, put {{-- @phpstan-ignore phpstanCwe.cwe79 (Reason) --}} immediately BEFORE this raw echo. Replace "Reason" with the reason.',
        );
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
