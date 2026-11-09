<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * A shared utility class to check for @phpstan-ignore annotations and their reasons.
 *
 * Limitations: t handles PHP AST comments, not Blade comments, baselines, or global ignoreErrors.
 * A rule should call it once per file, not once per visited node in order to avoid repeated scans and reports.
 */
final class IgnoreReason
{
    /**
     * @param array<Node> $nodes
     * @return list<IdentifierRuleError>
     */
    public static function reports(array $nodes, string $file, string $identifier, int $cwe): array
    {
        $reports = [];
        $seen = [];
        $commentedNodes = (new NodeFinder())->find($nodes, static fn (Node $node): bool => $node->getComments() !== []);
        foreach ($commentedNodes as $node) {
            foreach ($node->getComments() as $comment) {
                // The parser can attach one comment to more than one node.
                // Use its source position to avoid duplicate errors.
                if (isset($seen[$comment->getStartFilePos()])) {
                    continue;
                }
                $seen[$comment->getStartFilePos()] = $comment;
                if (!preg_match('/@phpstan-ignore\s+([^\r\n]*)/', $comment->getText(), $annotation)) {
                    continue;
                }
                // An annotation can list several identifiers. Each identifier
                // must have its own reason; a neighbouring reason does not apply.
                preg_match_all('/(?:^|,)\s*([a-zA-Z][a-zA-Z0-9.]*)(?:\s*\(([^)]*)\))?/', $annotation[1], $ignores, PREG_SET_ORDER);
                foreach ($ignores as $ignore) {
                    // Count words, not spaces. Punctuation alone is not a reason.
                    if ($ignore[1] !== $identifier
                        || preg_match_all("/[\\p{L}\\p{N}]+(?:[-'][\\p{L}\\p{N}]+)*/u", $ignore[2] ?? '') > 1
                    ) {
                        continue;
                    }
                    // The CWE finding can be ignored, but an invalid reason cannot.
                    $reports[] = RuleErrorBuilder::message(sprintf('CWE-%d ignore requires a reason with at least two words.', $cwe))
                        ->identifier('phpstanCwe.ignoreReason')
                        ->file($file)
                        ->line($comment->getStartLine())
                        ->nonIgnorable()
                        ->build();
                }
            }
        }

        return $reports;
    }
}
