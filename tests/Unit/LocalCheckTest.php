<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/******************************************************************************
 * This file is just for testing the `check` script and its local settings.
 * it's not part of the package's normal test suite.
 * @see ./check
 * @see ./.check.local.example
 *****************************************************************************/
beforeEach(function (): void {
    $this->checkDirectory = sys_get_temp_dir() . '/phpstan-cwe-check-' . bin2hex(random_bytes(8));
    mkdir($this->checkDirectory);
    copy(__DIR__ . '/../../check', $this->checkDirectory . '/check');
    file_put_contents($this->checkDirectory . '/composer', <<<'BASH'
#!/usr/bin/env bash
printf '%s\n' "$PWD" "$@" >> "$CHECK_LOG"
if [[ "${3:-}" == "${CHECK_FAIL_SCRIPT:-}" ]]; then
    exit 7
fi
BASH);
    chmod($this->checkDirectory . '/composer', 0700);
    $this->runCheck = fn (array $arguments = [], array $environment = []): Process => new Process(
        ['bash', $this->checkDirectory . '/check', ...$arguments],
        $this->checkDirectory,
        [
            'PATH' => $this->checkDirectory . PATH_SEPARATOR . getenv('PATH'),
            'CHECK_LOG' => $this->checkDirectory . '/commands',
            ...$environment,
        ],
    );
});

afterEach(function (): void {
    foreach (['composer', 'commands', 'check', '.check.local'] as $file) {
        if (is_file($this->checkDirectory . '/' . $file)) {
            unlink($this->checkDirectory . '/' . $file);
        }
    }
    rmdir($this->checkDirectory);
});

it('runs the default checks from the package root with test defaults', function (): void {
    $process = ($this->runCheck)();
    $process->mustRun();
    $root = $this->checkDirectory;

    expect(file_get_contents($this->checkDirectory . '/commands'))->toBe(implode("\n", [
        $root, 'run-script', '--timeout=0', 'format:check',
        $root, 'run-script', '--timeout=0', 'analyse',
        $root, 'run-script', '--timeout=0', 'test', '--', '--no-tia', '--parallel',
        $root, 'run-script', '--timeout=0', 'test:mutation:check', '--', '--no-tia', '--parallel', '--no-cache',
        '',
    ]));
});

it('passes extra arguments only to selected test scripts without shell expansion', function (): void {
    $process = ($this->runCheck)(['analyse', 'test', 'test:mutation:check', '--', '--processes=16', '--filter=two words; literal']);
    $process->mustRun();
    $commands = file_get_contents($this->checkDirectory . '/commands');

    expect($commands)->not->toContain('format:check')
        ->and(substr_count($commands, "--processes=16\n--filter=two words; literal\n"))->toBe(2)
        ->and($commands)->toContain("analyse\n" . $this->checkDirectory . "\n");
});

it('stops at the first failed script and keeps its exit code', function (): void {
    $process = ($this->runCheck)([], ['CHECK_FAIL_SCRIPT' => 'analyse']);
    $process->run();

    expect($process->getExitCode())->toBe(7)
        ->and(file_get_contents($this->checkDirectory . '/commands'))->not->toContain("\ntest\n", "\ntest:mutation:check\n");
});

it('rejects unknown scripts before running any checks', function (): void {
    $process = ($this->runCheck)(['test', 'unknown']);
    $process->run();

    expect($process->getExitCode())->toBe(2)
        ->and($process->getErrorOutput())->toContain('Unknown script or option: unknown')
        ->and(is_file($this->checkDirectory . '/commands'))->toBeFalse();
});

it('prints help without running checks', function (): void {
    $process = ($this->runCheck)(['--help']);
    $process->mustRun();

    expect($process->getOutput())->toContain('Usage: ./check')
        ->and(is_file($this->checkDirectory . '/commands'))->toBeFalse();
});

it('loads the example settings without changing the defaults', function (): void {
    copy(__DIR__ . '/../../.check.local.example', $this->checkDirectory . '/.check.local');
    ($this->runCheck)()->mustRun();
    $commands = file_get_contents($this->checkDirectory . '/commands');

    expect($commands)->toContain("format:check\n", "analyse\n", "test\n", "test:mutation:check\n")
        ->and(substr_count($commands, "--no-tia\n--parallel\n"))->toBe(2)
        ->and(substr_count($commands, "--no-cache\n"))->toBe(1);
});

it('uses local scripts and worker count for both test commands', function (): void {
    file_put_contents($this->checkDirectory . '/.check.local', <<<'BASH'
CHECK_SCRIPTS=(test:mutation:check test)
CHECK_PROCESSES=16
BASH);
    ($this->runCheck)()->mustRun();
    $commands = file_get_contents($this->checkDirectory . '/commands');

    expect($commands)->not->toContain("format:check\n", "analyse\n")
        ->and(strpos($commands, "test:mutation:check\n"))->toBeLessThan(strpos($commands, "test\n"))
        ->and(substr_count($commands, "--parallel\n--processes=16\n"))->toBe(2);
});

it('can disable parallel tests, test impact settings, and mutation cache settings', function (): void {
    file_put_contents($this->checkDirectory . '/.check.local', <<<'BASH'
CHECK_SCRIPTS=(test test:mutation:check)
CHECK_PARALLEL=false
CHECK_NO_TIA=false
CHECK_MUTATION_NO_CACHE=false
BASH);
    ($this->runCheck)()->mustRun();
    $commands = file_get_contents($this->checkDirectory . '/commands');

    expect($commands)->toContain("test\n--\n", "test:mutation:check\n--\n")
        ->not->toContain('--parallel', '--no-tia', '--no-cache', '--processes');
});

it('lets command-line script names replace the local script list', function (): void {
    file_put_contents($this->checkDirectory . '/.check.local', 'CHECK_SCRIPTS=(test)');
    ($this->runCheck)(['analyse'])->mustRun();

    expect(file_get_contents($this->checkDirectory . '/commands'))->toContain("analyse\n")
        ->not->toContain("test\n");
});

it('rejects invalid local settings before running checks', function (string $settings, string $message): void {
    file_put_contents($this->checkDirectory . '/.check.local', $settings);
    $process = ($this->runCheck)();
    $process->run();

    expect($process->getExitCode())->toBe(2)
        ->and($process->getErrorOutput())->toContain($message)
        ->and(is_file($this->checkDirectory . '/commands'))->toBeFalse();
})->with([
    ['CHECK_PARALLEL=yes', 'CHECK_PARALLEL must be true or false'],
    ['CHECK_NO_TIA=1', 'CHECK_NO_TIA must be true or false'],
    ['CHECK_MUTATION_NO_CACHE=no', 'CHECK_MUTATION_NO_CACHE must be true or false'],
    ['CHECK_PROCESSES=0', 'CHECK_PROCESSES requires a positive integer'],
    ['CHECK_PROCESSES=-1', 'CHECK_PROCESSES requires a positive integer'],
    ['CHECK_PROCESSES=abc', 'CHECK_PROCESSES requires a positive integer'],
    ["CHECK_PARALLEL=false\nCHECK_PROCESSES=16", 'CHECK_PROCESSES requires a positive integer'],
    ['CHECK_SCRIPTS=(analyse unknown)', 'Unknown script: unknown'],
    ['CHECK_SCRIPTS=()', 'Select at least one script'],
]);
