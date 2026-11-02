<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;

covers(BladeTemplateScanner::class);

it('finds raw Blade values and keeps template line numbers', function (): void {
    $directory = __DIR__ . '/../fixtures/CWE-79/blade/views';
    $findings = (new BladeTemplateScanner())->scan([$directory]);

    expect($findings)->toHaveCount(4)
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 3, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 9, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 12, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/parts/item.blade.php', 'line' => 1, 'type' => 'rawEcho']);
});

it('ignores only the raw echo next to a matching Blade comment', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-79/blade/ignores/ignored.blade.php';
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
    $findings = (new BladeTemplateScanner())->scan([__DIR__ . '/../fixtures/CWE-89']);

    expect($findings)->toBe([]);
});

it('does not report a view twice when directories overlap', function (): void {
    $directory = __DIR__ . '/../fixtures/CWE-79/blade/views';
    $findings = (new BladeTemplateScanner())->scan([$directory, $directory . '/parts']);

    expect($findings)->toHaveCount(4);
});

it('does not require a Laravel view directory in other projects', function (): void {
    expect((new BladeTemplateScanner())->scan(['resources/views']))->toBe([])
        ->and((new BladeTemplateScanner())->scan([]))->toBe([]);
});

it('reports an invalid configured view directory', function (): void {
    expect(fn () => (new BladeTemplateScanner())->scan(['tests/fixtures/CWE-79/no-views']))
        ->toThrow(InvalidArgumentException::class, 'Blade view directory does not exist');
});

it('reports an invalid working directory', function (): void {
    $workingDirectory = getcwd();
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    chdir($directory);

    try {
        expect(rmdir($directory))->toBeTrue()
            ->and(fn () => (new BladeTemplateScanner())->scan([]))
            ->toThrow(RuntimeException::class, 'Cannot get the current directory for the Blade scan.');
    } finally {
        chdir($workingDirectory);
    }
});

it('reports unreadable Blade templates', function (): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/unreadable.blade.php';
    file_put_contents($file, '{!! $value !!}');
    chmod($file, 0000);
    set_error_handler(static fn (int $severity): bool => $severity === E_WARNING);

    try {
        expect(fn () => (new BladeTemplateScanner())->scan([$directory]))
            ->toThrow(RuntimeException::class, 'Cannot read Blade view:');
    } finally {
        restore_error_handler();
        chmod($file, 0600);
        unlink($file);
        rmdir($directory);
    }
});

it('reports PCRE failures when scanning Blade templates', function (string $source, string $message): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/failure.blade.php';
    file_put_contents($file, $source);
    $backtrackLimit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.backtrack_limit', '1');

    try {
        expect(fn () => (new BladeTemplateScanner())->scan([$directory]))
            ->toThrow(RuntimeException::class, $message);
    } finally {
        ini_set('pcre.backtrack_limit', $backtrackLimit);
        unlink($file);
        rmdir($directory);
    }
})->with([
    'verbatim pattern' => ["@verbatim\n" . str_repeat('x', 10000), 'Cannot scan Blade view:'],
    'Blade comment pattern' => [str_repeat('{{--x', 500) . '--}}', 'Cannot scan Blade comments in view:'],
    'raw echo pattern' => [str_repeat('{!!x', 500) . '!!}', 'Cannot scan raw echoes in Blade view:'],
]);

it('handles raw echoes and ignore comments at text boundaries', function (string $source, array $expected): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/boundary.blade.php';
    file_put_contents($file, $source);
    try {
        $findings = (new BladeTemplateScanner())->scan([$directory]);
        expect($findings)->toBe(array_map(
            static fn (array $finding): array => ['file' => $file, ...$finding],
            $expected,
        ));
    } finally {
        unlink($file);
        rmdir($directory);
    }
})->with([
    'raw echo before trailing at sign' => ['{!! $value !!}@', [['line' => 1, 'type' => 'rawEcho']]],
    'escaped raw echo at start' => ['@{!! $value !!}', []],
    'ignore before trailing at sign' => ['{{-- @phpstan-ignore phpstanCwe.cwe79 --}}{!! $value !!}@', []],
    'ignore after one character' => ['x{{-- @phpstan-ignore phpstanCwe.cwe79 --}}{!! $value !!}', []],
    'first character newline' => ["\n{!! \$value !!}", [['line' => 2, 'type' => 'rawEcho']]],
    'ignore after newline' => ["\n{{-- @phpstan-ignore phpstanCwe.cwe79 --}}", [['line' => 2, 'type' => 'unmatchedIgnore']]],
    'ignore after raw echo' => ['{!! $value !!}{{-- @phpstan-ignore phpstanCwe.cwe79 --}}', [['line' => 1, 'type' => 'rawEcho'], ['line' => 1, 'type' => 'unmatchedIgnore']]],
]);

it('continues after missing default directories and duplicate views', function (): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $first = $directory . '/first';
    $second = $directory . '/second';
    mkdir($first);
    mkdir($second);
    $firstFile = $first . '/first.blade.php';
    $secondFile = $second . '/second.blade.php';
    file_put_contents($firstFile, '{!! $first !!}');
    file_put_contents($secondFile, '{!! $second !!}');
    mkdir($first . '/not-a-file.blade.php');
    try {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS));
        $iterator->rewind();
        $firstVisitedDirectory = $iterator->current()->getPath();
        $findings = (new BladeTemplateScanner())->scan(['resources/views', $firstVisitedDirectory, $directory]);
        expect($findings)->toHaveCount(2)
            ->and($findings)->toContain(['file' => $firstFile, 'line' => 1, 'type' => 'rawEcho'])
            ->and($findings)->toContain(['file' => $secondFile, 'line' => 1, 'type' => 'rawEcho']);
    } finally {
        unlink($firstFile);
        unlink($secondFile);
        rmdir($first . '/not-a-file.blade.php');
        rmdir($first);
        rmdir($second);
        rmdir($directory);
    }
});

it('does not scan raw echo text in other file types', function (): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/view.txt';
    file_put_contents($file, '{!! $value !!}');
    try {
        expect((new BladeTemplateScanner())->scan([$directory]))->toBe([]);
    } finally {
        unlink($file);
        rmdir($directory);
    }
});
