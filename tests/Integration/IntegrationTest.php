<?php

declare(strict_types=1);

function analyseWithConfig(string $config, string $fixture = 'tests/fixtures/shared/integration.php'): array
{
    $root = dirname(__DIR__, 2);
    $process = proc_open(
        [PHP_BINARY, $root . '/vendor/bin/phpstan', 'analyse', $root . '/' . $fixture,
            '--configuration=' . $root . '/' . $config, '--level=0', '--no-progress', '--error-format=json'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $root,
    );
    if (!is_resource($process)) {
        throw new RuntimeException('PHPStan did not start.');
    }

    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    $result = json_decode($output, true, 512, JSON_THROW_ON_ERROR);

    expect($result['errors'])->toBe([])
        ->and($status)->toBeIn([0, 1]);

    return $result;
}

it('loads both rules with identifiers and MITRE links', function (): void {
    $result = analyseWithConfig('extension.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(2)
        ->and(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.cwe89'])
        ->and(array_column($messages, 'line'))->toBe([3, 5])
        ->and($messages[0]['message'])->toContain(
            'Severity: high.',
            'Probability: 80%.',
            'https://cwe.mitre.org/data/definitions/79.html'
        )
        ->and($messages[1]['message'])->toContain(
            'Severity: high.',
            'Probability: 80%.',
            'https://cwe.mitre.org/data/definitions/89.html'
        )
        ->and(array_column($messages, 'ignorable'))->toBe([true, true]);
});

it('loads a single rule when selected', function (): void {
    $result = analyseWithConfig('cwe79.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe79']);

    $result = analyseWithConfig('cwe89.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe89']);
});

it('loads the Laravel SQL rule from its public configuration', function (): void {
    $result = analyseWithConfig('cwe89-laravel.neon', 'tests/fixtures/CWE-89/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];
    $expectedRequestMessage = 'CWE-89: Request input is used in Laravel raw SQL. Use a bound parameter. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html';
    $expectedUnknownMessage = 'CWE-89: Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter. Severity: high. Probability: 45%. https://cwe.mitre.org/data/definitions/89.html';

    expect($result['totals']['file_errors'])->toBe(19)
        ->and(array_keys($result['files']))
        ->toBe([dirname(__DIR__, 2) . '/tests/fixtures/CWE-89/laravel.php'])
        ->and(array_unique(array_column($messages, 'identifier')))
        ->toBe(['phpstanCwe.cwe89']);
    expect(array_column($messages, 'line'))->toBe([120, 121, 122, 123, 124, 125, 126, 127, 128, 131, 132, 134, 135, 141, 143, 145, 147, 151, 152]);
    foreach ($messages as $index => $message) {
        expect($message['message'])->toBe(in_array($index, [11, 12, 17, 18], true)
            ? $expectedUnknownMessage
            : $expectedRequestMessage)
            ->and($message['identifier'])->toBe('phpstanCwe.cwe89')
            ->and($message['ignorable'])->toBeTrue();
    }
});

it('filters reports below the minimum probability', function (): void {
    $result = analyseWithConfig('tests/fixtures/shared/filtered.neon');

    expect($result['totals']['file_errors'])->toBe(0);
});

it('reports Blade raw echoes at the view file and line', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-79/blade.neon');
    $templateFiles = [];

    foreach ($result['files'] as $path => $file) {
        if (str_ends_with($path, '.blade.php')) {
            $templateFiles[basename($path)] = $file['messages'];
        }
    }

    expect(array_keys($templateFiles))->toContain('home.blade.php', 'item.blade.php')
        ->and(array_column($templateFiles['home.blade.php'], 'line'))->toBe([3, 9, 12])
        ->and(array_column($templateFiles['item.blade.php'], 'line'))->toBe([1]);
    foreach ($templateFiles as $messages) {
        foreach ($messages as $message) {
            expect($message['identifier'])->toBe('phpstanCwe.cwe79')
                ->and($message['message'])->toContain(
                    'Severity: high.',
                    'Probability: 80%.',
                    'https://cwe.mitre.org/data/definitions/79.html'
                )
                ->and($message['ignorable'])->toBeTrue()
                ->and($message['tip'])->toBe('Only if you are sure that this value is safe HTML, put {{-- @phpstan-ignore phpstanCwe.cwe79 (Reason) --}} immediately BEFORE this raw echo. Replace "Reason" with the reason.');
        }
    }
});

it('loads the Blade rule without the PHP rules', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-79/blade-only.neon');

    expect($result['totals']['file_errors'])->toBe(4)
        ->and(array_keys($result['files']))->not->toContain(dirname(__DIR__, 2).'/tests/fixtures/shared/integration.php');
});

it('filters Blade reports below the minimum probability', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-79/filtered-blade.neon');

    expect($result['totals']['file_errors'])->toBe(0);
});

it('ignores one Blade echo and reports unused ignore comments at their lines', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-79/blade-ignores.neon');
    $messages = array_values($result['files'])[0]['messages'];
    $linesByIdentifier = [];

    foreach ($messages as $message) {
        $linesByIdentifier[$message['identifier']][] = $message['line'];
    }

    expect($linesByIdentifier['phpstanCwe.cwe79'])->toBe([3, 5, 8, 11, 14, 18, 20, 23, 24, 26])
        ->and($linesByIdentifier['phpstanCwe.ignoreUnmatched'])->toBe([6, 9, 12, 21]);
});
