<?php

declare(strict_types=1);

pest()->tia()->defaultBranch('main')->always();

require_once __DIR__ . '/Support/AnalysesWithoutFingerprints.php';

function withoutFingerprint(string $message): string
{
    return preg_replace('/ Fingerprint: [a-f0-9]{64}\./', '', $message);
}

function analyseWithConfig(string $config, string $fixture = 'tests/fixtures/shared/integration.php', bool $keepFingerprints = false): array
{
    $root = dirname(__DIR__);
    $process = proc_open(
        [PHP_BINARY, $root . '/vendor/bin/phpstan', 'analyse', str_starts_with($fixture, '/') ? $fixture : $root . '/' . $fixture,
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

    if (!$keepFingerprints) {
        foreach ($result['files'] as $file => $report) {
            foreach ($report['messages'] as $index => $message) {
                $result['files'][$file]['messages'][$index]['message'] = withoutFingerprint($message['message']);
            }
        }
    }

    return $result;
}
