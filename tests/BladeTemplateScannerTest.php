<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;

it('finds raw Blade values and keeps template line numbers', function (): void {
    $directory = __DIR__ . '/fixtures/blade/views';
    $findings = (new BladeTemplateScanner())->scan([$directory]);

    expect($findings)->toHaveCount(4)
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 3, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 9, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 12, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/parts/item.blade.php', 'line' => 1, 'type' => 'rawEcho']);
});

it('ignores only the raw echo next to a matching Blade comment', function (): void {
    $file = __DIR__ . '/blade-ignores/ignored.blade.php';
    $findings = (new BladeTemplateScanner())->scan([dirname($file)]);
    $linesByType = [];

    foreach ($findings as $finding) {
        expect($finding['file'])->toBe($file);
        $linesByType[$finding['type']][] = $finding['line'];
    }

    expect($linesByType['rawEcho'])->toBe([3, 5, 8, 11, 14, 18, 20, 23, 24, 26])
        ->and($linesByType['unmatchedIgnore'])->toBe([6, 9, 12, 21]);
});

it('does not scan files that are not Blade templates', function (): void {
    $findings = (new BladeTemplateScanner())->scan([__DIR__ . '/fixtures']);

    expect($findings)->toHaveCount(4);
});

it('does not report a view twice when directories overlap', function (): void {
    $directory = __DIR__ . '/fixtures/blade/views';
    $findings = (new BladeTemplateScanner())->scan([$directory, $directory . '/parts']);

    expect($findings)->toHaveCount(4);
});

it('does not require a Laravel view directory in other projects', function (): void {
    expect((new BladeTemplateScanner())->scan(['resources/views']))->toBe([])
        ->and((new BladeTemplateScanner())->scan([]))->toBe([]);
});

it('reports an invalid configured view directory', function (): void {
    expect(fn () => (new BladeTemplateScanner())->scan(['tests/fixtures/no-views']))
        ->toThrow(InvalidArgumentException::class, 'Blade view directory does not exist');
});
