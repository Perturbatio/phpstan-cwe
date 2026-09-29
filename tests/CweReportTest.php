<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\CweReport;
use PHPStan\Rules\FileRuleError;
use PHPStan\Rules\LineRuleError;
use PHPStan\Rules\MetadataRuleError;

it('keeps severity, score, link, and identifier in the report', function (): void {
    $report = CweReport::make(79, 'Direct input is in HTML.', 'high', 80);

    expect($report->getIdentifier())->toBe('phpstanCwe.cwe79');
    expect($report->getMessage())->toContain('Severity: high.', 'Probability: 80%.', 'https://cwe.mitre.org/data/definitions/79.html');
    expect($report)->toBeInstanceOf(MetadataRuleError::class);
    expect($report->getMetadata())->toBe([
        'cwe' => 79,
        'severity' => 'high',
        'probability' => 80,
        'url' => 'https://cwe.mitre.org/data/definitions/79.html',
    ]);
});

it('sets the template file and line when a rule scans a separate file', function (): void {
    $file = __DIR__ . '/fixtures/blade/views/home.blade.php';
    $report = CweReport::make(79, 'Blade raw output.', 'high', 80, $file, 7);

    expect($report)->toBeInstanceOf(FileRuleError::class);
    expect($report)->toBeInstanceOf(LineRuleError::class);
    expect($report->getFile())->toBe($file);
    expect($report->getLine())->toBe(7);
});

it('includes scores at the minimum and excludes lower scores', function (): void {
    expect(CweReport::isEnabled(0, 80))->toBeTrue();
    expect(CweReport::isEnabled(80, 80))->toBeTrue();
    expect(CweReport::isEnabled(81, 80))->toBeFalse();
    expect(CweReport::isEnabled(100, 100))->toBeTrue();
});
