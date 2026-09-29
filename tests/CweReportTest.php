<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\CweReport;
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

it('includes scores at the minimum and excludes lower scores', function (): void {
    expect(CweReport::isEnabled(0, 80))->toBeTrue();
    expect(CweReport::isEnabled(80, 80))->toBeTrue();
    expect(CweReport::isEnabled(81, 80))->toBeFalse();
    expect(CweReport::isEnabled(100, 100))->toBeTrue();
});
