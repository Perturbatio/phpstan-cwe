<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;
use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\RequestInput;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79BladeRule;
use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Collector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78IgnoreCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe78\Cwe78Rule;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelCollector;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89LaravelRule;
use Perturbatio\PhpstanCwe\Rules\Cwe89\Cwe89Rule;

// These tests check the package in a separate PHPStan process.
// Pest does not collect coverage from that process.
covers(
    AnalysedFileCollector::class,
    BladeTemplateScanner::class,
    CweReport::class,
    RequestInput::class,
    Cwe79BladeRule::class,
    Cwe79Rule::class,
    Cwe78Collector::class,
    Cwe78IgnoreCollector::class,
    Cwe78Rule::class,
    Cwe89LaravelCollector::class,
    Cwe89LaravelRule::class,
    Cwe89Rule::class,
);

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
    $result = analyseWithConfig('config/cwe78.neon', 'tests/fixtures/CWE-78/cwe78.php');
    expect(array_unique(array_column(array_values($result['files'])[0]['messages'], 'identifier')))
        ->toBe(['phpstanCwe.cwe78']);

    $result = analyseWithConfig('config/cwe79.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe79']);

    $result = analyseWithConfig('config/cwe89.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe89']);
});

it('checks Laravel request input at HTML output with both package configurations', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-79/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];
    $expectedLines = [52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 67, 68, 74, 85];
    $expectedMessage = 'CWE-79: Request input is sent to HTML without an HTML escape call. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/79.html';

    expect($result['totals']['file_errors'])->toBe(count($expectedLines))
        ->and(array_keys($result['files']))->toBe([dirname(__DIR__, 2) . '/tests/fixtures/CWE-79/laravel.php'])
        ->and(array_column($messages, 'line'))->toBe($expectedLines)
        ->and(array_column($messages, 'identifier'))->toBe(array_fill(0, count($expectedLines), 'phpstanCwe.cwe79'))
        ->and(array_column($messages, 'message'))->toBe(array_fill(0, count($expectedLines), $expectedMessage))
        ->and(array_column($messages, 'ignorable'))->toBe(array_fill(0, count($expectedLines), true));
})->with(['config/cwe79.neon', 'extension.neon']);

it('reports command sinks with context-based ratings and source lines', function (): void {
    $result = analyseWithConfig('config/cwe78.neon', 'tests/fixtures/CWE-78/cwe78.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(12)
        ->and(array_column($messages, 'identifier'))->toBe(array_fill(0, 12, 'phpstanCwe.cwe78'))
        ->and(array_column($messages, 'line'))->toBe([5, 6, 8, 11, 12, 13, 14, 15, 16, 17, 19, 20])
        ->and(array_column($messages, 'ignorable'))->toBe(array_fill(0, 12, true))
        ->and($messages[0]['message'])->toContain('Severity: very high.', 'Probability: 95%.', 'https://cwe.mitre.org/data/definitions/78.html')
        ->and($messages[1]['message'])->toContain('Severity: high.', 'Probability: 80%.', 'https://cwe.mitre.org/data/definitions/78.html')
        ->and(array_column($messages, 'message'))->toBe([
            'CWE-78: Request input is used as the full command. Use a fixed executable and safe arguments. Severity: very high. Probability: 95%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input changes an argument in a command with known text. Escape each argument or use a safe argument array. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input reaches a command through a local assignment. Check the command and its arguments. Severity: medium. Probability: 60%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input reaches a command through a local assignment. Check the command and its arguments. Severity: medium. Probability: 60%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Review this command for external input and unsafe command arguments. Severity: low. Probability: 50%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Review this command for external input and unsafe command arguments. Severity: low. Probability: 50%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input changes an argument in a command with known text. Escape each argument or use a safe argument array. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input changes an argument in a command with known text. Escape each argument or use a safe argument array. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input changes an argument in a command with known text. Escape each argument or use a safe argument array. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Review this command for external input and unsafe command arguments. Severity: low. Probability: 50%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input reaches a command through a local assignment. Check the command and its arguments. Severity: medium. Probability: 60%. https://cwe.mitre.org/data/definitions/78.html',
            'CWE-78: Request input is used as the full command. Use a fixed executable and safe arguments. Severity: very high. Probability: 95%. https://cwe.mitre.org/data/definitions/78.html',
        ]);
});

it('filters CWE-78 findings below the configured probability', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-78/filtered.neon', 'tests/fixtures/CWE-78/cwe78.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(2)
        ->and(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe78', 'phpstanCwe.cwe78'])
        ->and(array_column($messages, 'line'))->toBe([5, 20])
        ->and(array_column($messages, 'message'))->each->toContain('Probability: 95%.');
});

it('loads Laravel request command checks without duplicate reports', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-78/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];
    $expectedRatings = [
        52 => ['very high', 95],
        53 => ['high', 80],
        54 => ['very high', 95],
        55 => ['very high', 95],
        56 => ['very high', 95],
        57 => ['very high', 95],
        58 => ['very high', 95],
        60 => ['medium', 60],
        61 => ['low', 50],
        62 => ['low', 50],
        63 => ['low', 50],
        64 => ['very high', 95],
        66 => ['low', 50],
        67 => ['low', 50],
        68 => ['very high', 95],
        69 => ['high', 80],
        76 => ['very high', 95],
        77 => ['very high', 95],
        87 => ['low', 50],
        88 => ['very high', 95],
    ];

    expect($result['totals']['file_errors'])->toBe(count($expectedRatings))
        ->and(array_keys($result['files']))->toBe([dirname(__DIR__, 2) . '/tests/fixtures/CWE-78/laravel.php'])
        ->and(array_column($messages, 'line'))->toBe(array_keys($expectedRatings));

    foreach ($messages as $message) {
        [$severity, $probability] = $expectedRatings[$message['line']];
        expect($message['identifier'])->toBe('phpstanCwe.cwe78')
            ->and($message['ignorable'])->toBeTrue()
            ->and($message['message'])->toContain(
                'Severity: ' . $severity . '.',
                'Probability: ' . $probability . '%.',
                'https://cwe.mitre.org/data/definitions/78.html',
            );
    }
})->with(['config/cwe78-laravel.neon', 'extension.neon']);

it('keeps the base command configuration independent of Laravel request sources', function (): void {
    $result = analyseWithConfig('config/cwe78.neon', 'tests/fixtures/CWE-78/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect($messages)->toHaveCount(20)
        ->and(array_column($messages, 'message'))->each->toContain('Severity: low.', 'Probability: 50%.');
});

it('keeps Laravel findings at the minimum score and filters weaker findings', function (): void {
    $result = analyseWithConfig('tests/fixtures/CWE-78/laravel-filtered.neon', 'tests/fixtures/CWE-78/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'line'))->toBe([52, 53, 54, 55, 56, 57, 58, 64, 68, 69, 76, 77, 88])
        ->and($messages[1]['message'])->toContain('Probability: 80%.')
        ->and($messages[0]['message'])->toContain('Probability: 95%.');
});

it('requires at least two words in a CWE-78 ignore reason', function (): void {
    $result = analyseWithConfig('config/cwe78.neon', 'tests/fixtures/CWE-78/ignore.php');
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(1)
        ->and(array_column($messages, 'identifier'))->toBe(['phpstanCwe.ignoreReason'])
        ->and(array_column($messages, 'line'))->toBe([3])
        ->and($messages[0]['message'])->toBe('CWE-78 ignore requires a reason with at least two words.');
});

it('loads the Laravel SQL rule from its public configuration', function (): void {
    $result = analyseWithConfig('config/cwe89-laravel.neon', 'tests/fixtures/CWE-89/laravel.php');
    $messages = array_values($result['files'])[0]['messages'];
    $expectedRequestMessage = 'CWE-89: Request input is used in Laravel raw SQL. Use a bound parameter. Severity: high. Probability: 80%. https://cwe.mitre.org/data/definitions/89.html';
    $expectedUnknownMessage = 'CWE-89: Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter. Severity: high. Probability: 45%. https://cwe.mitre.org/data/definitions/89.html';
    // These message positions start at zero. Each one needs the warning
    // for an unknown source, not the message for known request input.
    $unknownSourceMessageIndices = [11, 12, 17, 18, 19, 20, 23, 24, 25, 26, 27];

    // List report lines only. A report on a protected example fails this test.
    $expectedReportLines = [
        121, 122, 123, 124, 125,
        126, 127, 128, 129, 132,
        133, 135, 136, 142, 144,
        146, 148, 152, 153, 157,
        158, 229, 230, 231, 232,
        233, 235, 241,
    ];
    expect($result['totals']['file_errors'])->toBe(28)
        ->and(array_keys($result['files']))
        ->toBe([dirname(__DIR__, 2).'/tests/fixtures/CWE-89/laravel.php'])
        ->and(array_unique(array_column($messages, 'identifier')))
        ->toBe(['phpstanCwe.cwe89'])
        ->and(array_column($messages, 'line'))->toBe($expectedReportLines);
    foreach ($messages as $index => $message) {
        expect($message['message'])->toBe(in_array($index, $unknownSourceMessageIndices, true)
            ? $expectedUnknownMessage
            : $expectedRequestMessage)
            ->and($message['identifier'])->toBe('phpstanCwe.cwe89')
            ->and($message['ignorable'])->toBeTrue()
            ->and($message['tip'])->toBe('If you use wrap() for an SQL identifier, verify that PHPStan knows the argument is a string and the receiver is Illuminate\Database\Grammar or a subclass. Add or correct parameter types where needed. A string type alone does not make raw SQL safe. Use bound parameters for values.');
    }
});

it('uses shared Laravel sources for raw SQL and direct database queries', function (string $config): void {
    $result = analyseWithConfig($config, 'tests/fixtures/CWE-89/laravel-input.php');
    $messages = array_values($result['files'])[0]['messages'];
    $laravelLines = [48, 49, 50, 51, 52, 53, 54, 55, 56, 58, 60, 82, 83];
    $databaseLines = [61, 62, 63, 64, 68, 69, 70, 85];
    $expectedLines = match ($config) {
        'config/cwe89-laravel.neon' => $laravelLines,
        'config/cwe89.neon' => $databaseLines,
        default => array_merge($laravelLines, $databaseLines),
    };
    sort($expectedLines);

    expect(array_column($messages, 'line'))->toBe($expectedLines)
        ->and(array_keys($result['files']))->toBe([dirname(__DIR__, 2) . '/tests/fixtures/CWE-89/laravel-input.php']);

    foreach ($messages as $message) {
        $probability = $message['line'] === 82 ? 45 : 80;
        expect($message['identifier'])->toBe('phpstanCwe.cwe89')
            ->and($message['ignorable'])->toBeTrue()
            ->and($message['message'])->toContain(
                'Severity: high.',
                'Probability: ' . $probability . '%.',
                'https://cwe.mitre.org/data/definitions/89.html',
            );
    }
})->with(['config/cwe89-laravel.neon', 'config/cwe89.neon', 'extension.neon']);

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
