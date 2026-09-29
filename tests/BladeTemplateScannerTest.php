<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;

it('finds raw Blade values and keeps template line numbers', function (): void {
    $directory = __DIR__ . '/fixtures/blade/views';
    $findings = (new BladeTemplateScanner())->scan([$directory]);

    expect($findings)->toHaveCount(4)
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 3])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 9])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 12])
        ->and($findings)->toContain(['file' => $directory.'/parts/item.blade.php', 'line' => 1]);
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
