<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use Perturbatio\PhpstanCwe\Rules\Cwe306\Cwe306LaravelRule;

// These tests check the shared package annotation in a separate PHPStan process.
covers(CweFingerprint::class, CweIgnoreCollector::class, CweIgnoreSet::class, ExpressionText::class, Cwe306LaravelRule::class);

const IGNORE_ROUTE_PRELUDE = <<<'PHP'
namespace Illuminate\Support\Facades {
    class Route
    {
        public static function post(string $uri, \Closure $action): void
        {
        }
    }
}

namespace {
    use Illuminate\Support\Facades\Route;

    function eraseAccounts(): void
    {
    }

PHP;

/**
 * @return array<string, array{config: string, cwe: int, prelude: string, statement: string, changed: string, suffix: string}>
 */
function ignoreRuleCases(): array
{
    return [
        'CWE-78' => ['config' => 'config/cwe78.neon', 'cwe' => 78, 'prelude' => '', 'statement' => "exec(\$_GET['command']);", 'changed' => "exec(\$_POST['command']);", 'suffix' => ''],
        'CWE-79' => ['config' => 'config/cwe79.neon', 'cwe' => 79, 'prelude' => '', 'statement' => "echo \$_GET['name'];", 'changed' => "echo \$_POST['name'];", 'suffix' => ''],
        'CWE-89' => ['config' => 'config/cwe89.neon', 'cwe' => 89, 'prelude' => '', 'statement' => "mysqli_query(\$link, 'SELECT ' . \$_GET['id']);", 'changed' => "mysqli_query(\$link, 'SELECT ' . \$_POST['id']);", 'suffix' => ''],
        'CWE-95' => ['config' => 'config/cwe95.neon', 'cwe' => 95, 'prelude' => '', 'statement' => "eval(\$_GET['code']);", 'changed' => "eval(\$_POST['code']);", 'suffix' => ''],
        'CWE-306' => [
            'config' => 'tests/fixtures/CWE-306/laravel.neon', 'cwe' => 306, 'prelude' => IGNORE_ROUTE_PRELUDE,
            'statement' => "Route::post('/erase', function (): void {\n        eraseAccounts();\n    });",
            'changed' => "Route::post('/remove', function (): void {\n        eraseAccounts();\n    });", 'suffix' => "\n}\n",
        ],
    ];
}

/**
 * @param list<string> $statements
 */
function ignoreFixtureCode(array $case, array $statements): string
{
    $indent = $case['cwe'] === 306 ? '    ' : '';

    return "<?php\n\n" . $case['prelude'] . implode("\n", array_map(
        static fn (string $statement): string => $indent . $statement,
        $statements,
    )) . "\n" . $case['suffix'];
}

/**
 * @return array{messages: list<array<string, mixed>>, findings: list<array<string, mixed>>, ignoreErrors: list<string>}
 */
function analyseIgnoreFixture(string $config, string $file, string $code, int $cwe): array
{
    file_put_contents($file, $code);
    $result = analyseWithConfig($config, $file, true);
    $messages = array_values($result['files'])[0]['messages'] ?? [];

    return [
        'messages' => $messages,
        'findings' => array_values(array_filter($messages, static fn (array $message): bool => $message['identifier'] === 'phpstanCwe.cwe' . $cwe)),
        'ignoreErrors' => array_column(array_filter($messages, static fn (array $message): bool => str_starts_with($message['identifier'], 'phpstanCwe.ignore')), 'identifier'),
    ];
}

function ignoreFingerprintOf(array $finding): string
{
    preg_match('/Fingerprint: ([a-f0-9]{64})\./', $finding['message'], $matches);

    return $matches[1];
}

function withIgnoreFixture(callable $callback): void
{
    $file = tempnam(sys_get_temp_dir(), 'phpstan-ignore-');
    if ($file === false) {
        throw new RuntimeException('Cannot create a temporary PHP fixture.');
    }

    try {
        $callback($file);
    } finally {
        unlink($file);
    }
}

it('invalidates a CWE-95 annotation when the assigned request key changes', function (
    string $config,
    string $parameter,
    string $read,
    int $probability,
): void {
    withIgnoreFixture(function (string $file) use ($config, $parameter, $read, $probability): void {
        $code = "<?php\n\nfunction reviewCode($parameter): void\n{\n    \$code = $read;\n    eval(\$code);\n}\n";
        $code .= "\nclass OtherInput { public function input(string \$key): string { return \$key; } }\n";
        $baseline = analyseIgnoreFixture($config, $file, $code, 95);
        expect($baseline['findings'])->toHaveCount(1)
            ->and($baseline['findings'][0]['message'])->toContain("Probability: $probability%.");
        $fingerprint = ignoreFingerprintOf($baseline['findings'][0]);

        $ignored = str_replace(
            '    eval($code);',
            "    // Review the source.\n\n    // @phpstan-ignore phpstanCwe.cwe95.$fingerprint (Reviewed source)\n    eval(\$code);",
            $code,
        );
        expect(analyseIgnoreFixture($config, $file, $ignored, 95)['messages'])->toBe([]);

        $changed = analyseIgnoreFixture($config, $file, str_replace('codes-2', 'codes*2', $ignored), 95);
        expect(array_column($changed['messages'], 'identifier'))->toBe(['phpstanCwe.ignoreUnmatched', 'phpstanCwe.cwe95'])
            ->and(array_column($changed['messages'], 'line'))->toBe([8, 9])
            ->and(ignoreFingerprintOf($changed['findings'][0]))->not->toBe($fingerprint);
    });
})->with(['config/cwe95-laravel.neon', 'tests/fixtures/shared/extension.neon'])->with([
    'typed request' => ['\Illuminate\Http\Request $request', '$request->input(\'codes-2\')', 90],
    'untyped request' => ['$request', '$request->input(\'codes-2\')', 60],
    'request helper' => ['', 'request(\'codes-2\')', 90],
    'unrelated receiver' => ['OtherInput $other', '$other->input(\'codes-2\')', 60],
]);

it('suppresses exactly one finding with a package annotation', function (string $name): void {
    $case = ignoreRuleCases()[$name];
    withIgnoreFixture(function (string $file) use ($case): void {
        $statement = $case['statement'];
        $baseline = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$statement, $statement]), $case['cwe']);
        expect($baseline['findings'])->toHaveCount(2)
            ->and($baseline['ignoreErrors'])->toBe([])
            ->and(ignoreFingerprintOf($baseline['findings'][0]))->toBe(ignoreFingerprintOf($baseline['findings'][1]))
            ->and($baseline['findings'][0]['tip'])->toContain(sprintf('@phpstan-ignore phpstanCwe.cwe%d.%s (<reason>)', $case['cwe'], ignoreFingerprintOf($baseline['findings'][0])));

        $ignore = sprintf('// @phpstan-ignore phpstanCwe.cwe%d.%s (Reviewed input)', $case['cwe'], ignoreFingerprintOf($baseline['findings'][0]));
        $ignored = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$ignore, $statement, $statement]), $case['cwe']);
        expect($ignored['messages'])->toBe($ignored['findings'])
            ->and($ignored['findings'])->toHaveCount(1)
            ->and($ignored['ignoreErrors'])->toBe([]);

        $both = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$ignore, $statement, $ignore, $statement]), $case['cwe']);
        expect($both['messages'])->toBe([])
            ->and($both['ignoreErrors'])->toBe([]);
    });
})->with(array_keys(ignoreRuleCases()));

it('reports malformed hashes, short reasons and stale package annotations', function (string $name): void {
    $case = ignoreRuleCases()[$name];
    withIgnoreFixture(function (string $file) use ($case): void {
        $statement = $case['statement'];
        $cwe = $case['cwe'];
        $baseline = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$statement]), $cwe);
        $fingerprint = ignoreFingerprintOf($baseline['findings'][0]);

        $malformed = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ["// @phpstan-ignore phpstanCwe.cwe{$cwe}.abc (Reviewed input)", $statement]), $cwe);
        expect(array_column($malformed['messages'], 'identifier'))->toEqualCanonicalizing(['phpstanCwe.ignoreFingerprint', 'phpstanCwe.cwe' . $cwe])
            ->and($malformed['ignoreErrors'])->toBe(['phpstanCwe.ignoreFingerprint'])
            ->and($malformed['findings'])->toHaveCount(1);

        $short = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ["// @phpstan-ignore phpstanCwe.cwe{$cwe}.{$fingerprint} (Reviewed)", $statement]), $cwe);
        expect($short['ignoreErrors'])->toBe(['phpstanCwe.ignoreReason'])
            ->and($short['findings'])->toHaveCount(1);

        $missing = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ["// @phpstan-ignore phpstanCwe.cwe{$cwe}.{$fingerprint}", $statement]), $cwe);
        expect($missing['ignoreErrors'])->toBe(['phpstanCwe.ignoreReason'])
            ->and($missing['findings'])->toHaveCount(1);

        $stale = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ["// @phpstan-ignore phpstanCwe.cwe{$cwe}." . str_repeat('a', 64) . ' (Reviewed input)', $statement]), $cwe);
        expect($stale['ignoreErrors'])->toBe(['phpstanCwe.ignoreUnmatched'])
            ->and($stale['findings'])->toHaveCount(1);

        $otherCwe = $cwe === 78 ? 79 : 78;
        $other = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ["// @phpstan-ignore phpstanCwe.cwe{$otherCwe}." . str_repeat('b', 64) . ' (Reviewed input)', $statement]), $cwe);
        expect($other['ignoreErrors'])->toBe([])
            ->and($other['findings'])->toHaveCount(1);
    });
})->with(array_keys(ignoreRuleCases()));

it('keeps native unmatched annotations next to a package annotation', function (): void {
    $case = ignoreRuleCases()['CWE-79'];
    withIgnoreFixture(function (string $file) use ($case): void {
        $statement = $case['statement'];
        $baseline = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$statement]), 79);
        $fingerprint = ignoreFingerprintOf($baseline['findings'][0]);
        $ignore = "// @phpstan-ignore phpstanCwe.cwe79.$fingerprint (Reviewed output), example.unmatched (Native ignore)";
        $result = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$ignore, $statement]), 79);

        expect(array_column($result['messages'], 'identifier'))->toBe(['ignore.unmatchedIdentifier'])
            ->and($result['messages'][0]['message'])->toContain('example.unmatched');
    });
});

it('keeps fingerprints stable across runs and comments and changes them for relevant edits', function (string $name): void {
    $case = ignoreRuleCases()[$name];
    withIgnoreFixture(function (string $file) use ($case): void {
        $statement = $case['statement'];
        $first = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$statement]), $case['cwe']);
        $second = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$statement]), $case['cwe']);
        $fingerprint = ignoreFingerprintOf($first['findings'][0]);
        expect($second['findings'])->toBe($first['findings']);

        $moved = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, ['// Extra comment.', '', '', $statement]), $case['cwe']);
        expect($moved['findings'][0]['line'])->not->toBe($first['findings'][0]['line'])
            ->and(ignoreFingerprintOf($moved['findings'][0]))->toBe($fingerprint);

        $changed = analyseIgnoreFixture($case['config'], $file, ignoreFixtureCode($case, [$case['changed']]), $case['cwe']);
        expect(ignoreFingerprintOf($changed['findings'][0]))->not->toBe($fingerprint);
    });
})->with(array_keys(ignoreRuleCases()));

it('keeps package annotations working when all rules are loaded together', function (): void {
    withIgnoreFixture(function (string $file): void {
        $code = "<?php\n\neval(\$_GET['code']);\necho \$_GET['name'];\n";
        $baseline = analyseIgnoreFixture('tests/fixtures/shared/extension.neon', $file, $code, 95);
        $html = analyseIgnoreFixture('tests/fixtures/shared/extension.neon', $file, $code, 79);
        $ignores = sprintf(
            "<?php\n\n// @phpstan-ignore phpstanCwe.cwe95.%s (Reviewed input)\neval(\$_GET['code']);\n// @phpstan-ignore phpstanCwe.cwe79.%s (Reviewed input)\necho \$_GET['name'];\n",
            ignoreFingerprintOf($baseline['findings'][0]),
            ignoreFingerprintOf($html['findings'][0]),
        );
        $result = analyseIgnoreFixture('tests/fixtures/shared/extension.neon', $file, $ignores, 95);

        expect($result['messages'])->toBe([]);
    });
});

it('loads the direct and Laravel SQL configurations together without duplicate reports', function (): void {
    $direct = analyseWithConfig('config/cwe89.neon', 'tests/fixtures/CWE-89/cwe89.php', true);
    $both = analyseWithConfig('tests/fixtures/CWE-89/both.neon', 'tests/fixtures/CWE-89/cwe89.php', true);

    expect(array_values($both['files'])[0]['messages'])->toBe(array_values($direct['files'])[0]['messages'])
        ->and($both['totals']['file_errors'])->toBe(6);
});

it('applies package annotations to Blade raw echoes', function (): void {
    $directory = dirname(__DIR__) . '/fixtures/CWE-79/blade/package-ignores';
    $view = $directory . '/view.blade.php';
    mkdir($directory);
    $analyse = static function (string $template) use ($view): array {
        file_put_contents($view, $template);
        $result = analyseWithConfig('tests/fixtures/CWE-79/blade-package-ignores.neon', 'tests/fixtures/shared/integration.php', true);

        return array_values($result['files'])[0]['messages'] ?? [];
    };
    $identifiers = static fn (array $messages): array => array_column($messages, 'identifier');

    try {
        $echo = '{!! $name !!}';
        $baseline = $analyse("<div>\n{$echo}\n{$echo}\n</div>\n");
        $fingerprint = ignoreFingerprintOf($baseline[0]);
        $ignore = "{{-- @phpstan-ignore phpstanCwe.cwe79.{$fingerprint} (Reviewed output) --}}";

        expect($identifiers($baseline))->toBe(['phpstanCwe.cwe79', 'phpstanCwe.cwe79'])
            ->and(ignoreFingerprintOf($baseline[1]))->toBe($fingerprint)
            ->and($baseline[0]['tip'])->toContain("@phpstan-ignore phpstanCwe.cwe79.{$fingerprint} (<reason>)");

        $one = $analyse("<div>\n{$ignore}\n{$echo}\n{$echo}\n</div>\n");
        expect($identifiers($one))->toBe(['phpstanCwe.cwe79'])
            ->and($one[0]['line'])->toBe(4);

        expect($analyse("{$ignore}\n{$echo}\n{$ignore}\n{$echo}\n"))->toBe([]);

        $moved = $analyse("{{-- Extra comment. --}}\n\n<p>Text</p>\n{$echo}\n");
        expect(ignoreFingerprintOf($moved[0]))->toBe($fingerprint);

        $malformed = $analyse("{{-- @phpstan-ignore phpstanCwe.cwe79.abc (Reviewed output) --}}\n{$echo}\n");
        expect($identifiers($malformed))->toContain('phpstanCwe.ignoreFingerprint', 'phpstanCwe.cwe79');

        $short = $analyse("{{-- @phpstan-ignore phpstanCwe.cwe79.{$fingerprint} (Reviewed) --}}\n{$echo}\n");
        expect($identifiers($short))->toContain('phpstanCwe.ignoreReason', 'phpstanCwe.cwe79');

        $stale = $analyse('{{-- @phpstan-ignore phpstanCwe.cwe79.' . str_repeat('c', 64) . " (Reviewed output) --}}\n{$echo}\n");
        expect($identifiers($stale))->toContain('phpstanCwe.ignoreUnmatched', 'phpstanCwe.cwe79');

        $changed = $analyse('{!! $other !!}');
        expect(ignoreFingerprintOf($changed[0]))->not->toBe($fingerprint);

        $legacy = $analyse("{{-- @phpstan-ignore phpstanCwe.cwe79 (Reviewed output) --}}\n{$echo}\n");
        expect($identifiers($legacy))->toEqualCanonicalizing(['phpstanCwe.ignoreFingerprint','phpstanCwe.cwe79']);
    } finally {
        if (file_exists($view)) {
            unlink($view);
        }
        rmdir($directory);
    }
});

it('puts the class, function, and file scope into direct CWE-89 fingerprints', function (): void {
    $file = dirname(__DIR__) . '/fixtures/CWE-89/scoped.php';
    $result = analyseWithConfig('config/cwe89.neon', $file, true);
    $fingerprints = array_map(ignoreFingerprintOf(...), array_values($result['files'])[0]['messages']);
    $expression = static fn (string $function): string => $function . ': \'SELECT * FROM users WHERE id = \' . $_GET[\'id\']';

    expect($fingerprints)->toBe([
        CweFingerprint::make(89, [$file, 'Repo::find', 'direct', $expression('mysqli_query')]),
        CweFingerprint::make(89, [$file, '::findUser', 'direct', $expression('mysqli_query')]),
        CweFingerprint::make(89, [$file, '::file', 'direct', $expression('mysqli_query')]),
    ]);
});
