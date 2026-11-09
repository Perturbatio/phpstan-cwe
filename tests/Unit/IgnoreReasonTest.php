<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\IgnoreReason;
use PhpParser\ParserFactory;

covers(IgnoreReason::class);

it('requires more than one word in each CWE-306 ignore reason', function (string $annotation, int $count): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse("<?php\n// $annotation\noperation();");
    $reports = IgnoreReason::reports($nodes, __FILE__, 'phpstanCwe.cwe306', 306);

    expect($reports)->toHaveCount($count);
    if ($count === 0) {
        return;
    }
    expect($reports[0]->getMessage())->toBe('CWE-306 ignore requires a reason with at least two words.')
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.ignoreReason')
        ->and($reports[0]->getLine())->toBe(2)
        ->and($reports[0])->toBeInstanceOf(PHPStan\Rules\NonIgnorableRuleError::class);
})->with([
    ['@phpstan-ignore phpstanCwe.cwe306', 1],
    ['@phpstan-ignore phpstanCwe.cwe306 (safe)', 1],
    ['@phpstan-ignore phpstanCwe.cwe306 (well-known)', 1],
    ['@phpstan-ignore phpstanCwe.cwe306 (--- ...)', 1],
    ['@phpstan-ignore phpstanCwe.cwe306 (External authentication)', 0],
    ['@phpstan-ignore phpstanCwe.cwe306 (External   authentication)', 0],
    ['@phpstan-ignore phpstanCwe.cwe306 (External authentication), phpstanCwe.cwe306 (safe)', 1],
    ['@phpstan-ignore other.rule (Other reason), phpstanCwe.cwe306 (safe)', 1],
    ['@phpstan-ignore other.rule (Other reason)', 0],
    ['An ordinary comment.', 0],
]);

it('checks a shared comment only once', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse("<?php\n// @phpstan-ignore phpstanCwe.cwe306 (safe)\noperation();");
    $nodes[] = $nodes[0];
    expect(IgnoreReason::reports($nodes, __FILE__, 'phpstanCwe.cwe306', 306))->toHaveCount(1);
});

it('checks an ignore after an ordinary comment on the same statement', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
// This route uses external authentication.
// @phpstan-ignore phpstanCwe.cwe306 (safe)
operation();
PHP);
    $reports = IgnoreReason::reports($nodes, __FILE__, 'phpstanCwe.cwe306', 306);

    expect($reports)->toHaveCount(1)
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.ignoreReason')
        ->and($reports[0]->getMessage())->toBe('CWE-306 ignore requires a reason with at least two words.')
        ->and($reports[0]->getLine())->toBe(3);
});

it('checks new comments after a shared comment on the same statement', function (): void {
    $nodes = (new ParserFactory())->createForNewestSupportedVersion()->parse(<<<'PHP'
<?php
// @phpstan-ignore phpstanCwe.cwe306 (safe)
firstOperation();
// @phpstan-ignore phpstanCwe.cwe306
secondOperation();
PHP);
    // Keep a shared comment before the second statement's own comment.
    // A duplicate must not stop the check of the remaining comments.
    $nodes[1]->setAttribute('comments', [...$nodes[0]->getComments(), ...$nodes[1]->getComments()]);
    $reports = IgnoreReason::reports($nodes, __FILE__, 'phpstanCwe.cwe306', 306);

    expect($reports)->toHaveCount(2)
        ->and(array_map(static fn ($report): int => $report->getLine(), $reports))->toBe([2, 4])
        ->and(array_map(static fn ($report): string => $report->getIdentifier(), $reports))
        ->toBe(['phpstanCwe.ignoreReason', 'phpstanCwe.ignoreReason']);
});
