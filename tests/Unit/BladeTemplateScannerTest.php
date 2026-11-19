<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;

covers(BladeTemplateScanner::class);

/**
 * @param list<array<string, mixed>> $findings
 * @return list<array<string, mixed>>
 */
function withoutBladeIdentity(array $findings): array
{
    return array_map(
        static fn (array $finding): array => array_diff_key($finding, ['offset' => true, 'fingerprint' => true, 'ignore' => true]),
        $findings,
    );
}

it('finds raw Blade values and keeps template line numbers', function (): void {
    $directory = __DIR__ . '/../fixtures/CWE-79/blade/views';
    $findings = withoutBladeIdentity((new BladeTemplateScanner())->scan([$directory]));

    expect($findings)->toHaveCount(4)
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 3, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 9, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/home.blade.php', 'line' => 12, 'type' => 'rawEcho'])
        ->and($findings)->toContain(['file' => $directory.'/parts/item.blade.php', 'line' => 1, 'type' => 'rawEcho']);
});

it('finds raw echoes and malformed package annotations in the same Blade view', function (): void {
    $file = __DIR__ . '/../fixtures/CWE-79/blade/ignores/ignored.blade.php';
    $findings = (new BladeTemplateScanner())->scan([dirname($file)]);

    $linesByType = [];
    foreach ($findings as $finding) {
        $linesByType[$finding['type']][] = $finding['line'];
    }

    expect($linesByType['rawEcho'])->toEqualCanonicalizing([2, 3, 4, 5, 8, 11, 14, 18, 20, 23, 24, 24, 26])
        ->and($linesByType['packageIgnore'])->toEqualCanonicalizing([1, 4, 6, 9, 12, 21, 24]);
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

it('handles raw echoes and annotation comments at text boundaries', function (string $source, array $expected): void {
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $file = $directory . '/boundary.blade.php';
    file_put_contents($file, $source);
    try {
        $findings = withoutBladeIdentity((new BladeTemplateScanner())->scan([$directory]));
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
    'annotation before trailing at sign' => ['{{-- @phpstan-ignore phpstanCwe.cwe79 --}}{!! $value !!}@', [['line' => 1, 'type' => 'rawEcho'], ['line' => 1, 'type' => 'packageIgnore']]],
    'annotation after one character' => ['x{{-- @phpstan-ignore phpstanCwe.cwe79 --}}{!! $value !!}', [['line' => 1, 'type' => 'rawEcho'], ['line' => 1, 'type' => 'packageIgnore']]],
    'first character newline' => ["\n{!! \$value !!}", [['line' => 2, 'type' => 'rawEcho']]],
    'annotation after newline' => ["\n{{-- @phpstan-ignore phpstanCwe.cwe79 --}}", [['line' => 2, 'type' => 'packageIgnore']]],
    'annotation after raw echo' => ['{!! $value !!}{{-- @phpstan-ignore phpstanCwe.cwe79 --}}', [['line' => 1, 'type' => 'rawEcho'], ['line' => 1, 'type' => 'packageIgnore']]],
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
        $findings = withoutBladeIdentity((new BladeTemplateScanner())->scan(['resources/views', $firstVisitedDirectory, $directory]));
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

/**
 * @param array<string, string> $views
 * @return array<string, list<array<string, mixed>>>
 */
function scanBladeViews(array $views): array
{
    $directory = sys_get_temp_dir() . '/phpstan-cwe-' . bin2hex(random_bytes(8));
    mkdir($directory);
    $result = [];

    try {
        foreach ($views as $name => $contents) {
            file_put_contents($directory . '/' . $name, $contents);
        }
        foreach ((new BladeTemplateScanner())->scan([$directory]) as $finding) {
            $result[basename($finding['file'])][] = $finding;
        }
    } finally {
        foreach (array_keys($views) as $name) {
            unlink($directory . '/' . $name);
        }
        rmdir($directory);
    }

    return $result;
}

it('reports exact package annotation data and attaches it to the echo that follows', function (): void {
    $hash = str_repeat('A', 64);
    $comment = "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (  checked value  ) --}}";
    $result = scanBladeViews([
        'adjacent.blade.php' => "\n\n$comment{!! \$a !!}",
        'unmatched.blade.php' => "\n$comment text",
        'bare.blade.php' => "{{-- @phpstan-ignore phpstanCwe.cwe79 --}}\n{!! \$a !!}",
    ])['adjacent.blade.php'] ?? [];
    $adjacent = $result[1];

    expect($adjacent['type'])->toBe('packageIgnore')
        ->and($adjacent['line'])->toBe(3)
        ->and($adjacent['ignore'])->toBe([
            'cwe' => 79,
            'file' => $adjacent['file'],
            'line' => 3,
            'startOffset' => 2 + strlen($comment),
            'endOffset' => 2 + strlen($comment),
            'startLine' => 3,
            'endLine' => 3,
            'fingerprint' => str_repeat('a', 64),
            'reason' => 'checked value',
        ]);
});

it('reports a package annotation without an echo with offset minus one and a bare annotation with empty values', function (): void {
    $views = scanBladeViews([
        'unmatched.blade.php' => "\n{{-- @phpstan-ignore phpstanCwe.cwe79 --}} text",
    ]);
    $ignore = $views['unmatched.blade.php'][0]['ignore'];

    expect($views['unmatched.blade.php'])->toHaveCount(1)
        ->and($ignore['startOffset'])->toBe(-1)
        ->and($ignore['endOffset'])->toBe(-1)
        ->and($ignore['line'])->toBe(2)
        ->and($ignore['fingerprint'])->toBe('')
        ->and($ignore['reason'])->toBe('');
});

it('scans every comment after an escaped comment and after a package annotation', function (): void {
    $hash = str_repeat('a', 64);
    $views = scanBladeViews([
        'mixed.blade.php' => "@{{-- @phpstan-ignore phpstanCwe.cwe79 --}}\n"
            . "{{-- @phpstan-ignore phpstanCwe.cwe79.$hash (checked value) --}}\n"
            . "{{-- @phpstan-ignore phpstanCwe.cwe79 (Checked value) --}}{!! \$a !!}\n",
    ]);
    $types = array_column($views['mixed.blade.php'], 'type');

    expect($types)->toBe(['rawEcho', 'packageIgnore', 'packageIgnore']);
});

it('keeps the same fingerprint when whitespace in the raw echo changes', function (): void {
    $views = scanBladeViews([
        'a.blade.php' => '{!! $a   .   $b !!}',
        'b.blade.php' => "{!! \$a\n .\t\$b !!}",
    ]);
    $first = $views['a.blade.php'][0];
    $second = $views['b.blade.php'][0];

    expect($first['fingerprint'])->toMatch('/^[a-f0-9]{64}$/')
        ->and($first['fingerprint'])->toBe(\Perturbatio\PhpstanCwe\Ignore\CweFingerprint::make(79, [$first['file'], 'blade', '$a . $b']))
        ->and($second['fingerprint'])->toBe(\Perturbatio\PhpstanCwe\Ignore\CweFingerprint::make(79, [$second['file'], 'blade', '$a . $b']));
});
