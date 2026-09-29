<?php

declare(strict_types=1);

function analyseWithConfig(string $config): array
{
    $root = dirname(__DIR__);
    $process = proc_open(
        [PHP_BINARY, $root . '/vendor/bin/phpstan', 'analyse', $root . '/tests/fixtures/integration.php',
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

    expect($status)->toBeIn([0, 1]);

    return json_decode($output, true, 512, JSON_THROW_ON_ERROR);
}

it('loads both rules with identifiers and MITRE links', function (): void {
    $result = analyseWithConfig('extension.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect($result['totals']['file_errors'])->toBe(2);
    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.cwe89']);
    expect(array_column($messages, 'line'))->toBe([3, 5]);
    expect($messages[0]['message'])->toContain('Severity: high.', 'Probability: 80%.', 'https://cwe.mitre.org/data/definitions/79.html');
    expect($messages[1]['message'])->toContain('Severity: high.', 'Probability: 80%.', 'https://cwe.mitre.org/data/definitions/89.html');
    expect(array_column($messages, 'ignorable'))->toBe([true, true]);
});

it('loads a single rule when selected', function (): void {
    $result = analyseWithConfig('cwe79.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe79']);

    $result = analyseWithConfig('cwe89.neon');
    $messages = array_values($result['files'])[0]['messages'];

    expect(array_column($messages, 'identifier'))->toBe(['phpstanCwe.cwe89']);
});

it('filters reports below the minimum probability', function (): void {
    $result = analyseWithConfig('tests/fixtures/filtered.neon');

    expect($result['totals']['file_errors'])->toBe(0);
});
