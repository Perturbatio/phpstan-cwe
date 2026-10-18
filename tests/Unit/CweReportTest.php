<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\CweReport;
use PHPStan\Rules\FileRuleError;
use PHPStan\Rules\LineRuleError;
use PHPStan\Rules\MetadataRuleError;
use PHPStan\Rules\TipRuleError;

it('keeps severity, score, link, and identifier in the report', function (): void {
    $report = CweReport::make(79, 'Direct input is in HTML.', 'high', 80);

    expect($report->getIdentifier())->toBe('phpstanCwe.cwe79')
        ->and($report->getMessage())->toContain(
            'Severity: high.',
            'Probability: 80%.',
            'https://cwe.mitre.org/data/definitions/79.html'
        )
        ->and($report)->toBeInstanceOf(MetadataRuleError::class)
        ->and($report->getMetadata())->toBe([
            'cwe' => 79,
            'severity' => 'high',
            'probability' => 80,
            'url' => 'https://cwe.mitre.org/data/definitions/79.html',
        ]);
});

it('sets the template file and line when a rule scans a separate file', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-79/blade/views/home.blade.php';
    $report = CweReport::make(79, 'Blade raw output.', 'high', 80, $file, 7);

    expect($report)->toBeInstanceOf(FileRuleError::class)
        ->and($report)->toBeInstanceOf(LineRuleError::class)
        ->and($report->getFile())->toBe($file)
        ->and($report->getLine())->toBe(7);
});

it('adds a tip only when a rule gives one', function (): void {
    $reportWithTip = CweReport::make(79, 'Blade raw output.', 'high', 80, tip: 'Review the value.');
    $reportWithoutTip = CweReport::make(79, 'Blade raw output.', 'high', 80);

    expect($reportWithTip)->toBeInstanceOf(TipRuleError::class)
        ->and($reportWithTip->getTip())->toBe('Review the value.')
        ->and($reportWithoutTip)->not->toBeInstanceOf(TipRuleError::class);
});

it('includes scores at the minimum and excludes lower scores', function (): void {
    expect(CweReport::isEnabled(0, 80))->toBeTrue()
        ->and(CweReport::isEnabled(80, 80))->toBeTrue()
        ->and(CweReport::isEnabled(81, 80))->toBeFalse()
        ->and(CweReport::isEnabled(100, 100))->toBeTrue();
});
