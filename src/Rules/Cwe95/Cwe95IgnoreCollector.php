<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @phpstan-type Cwe95IgnoreEvent array{
 *     file: string,
 *     line: int,
 *     startOffset: int,
 *     endOffset: int,
 *     fingerprint: string,
 *     reason: string
 * }
 * @implements Collector<Node, Cwe95IgnoreEvent|null>
 */
final class Cwe95IgnoreCollector implements Collector
{
    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return Cwe95IgnoreEvent|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node instanceof Stmt) {
            return null;
        }

        foreach ($node->getComments() as $comment) {
            if (!str_contains($comment->getText(), '@phpstan-cwe-ignore')) {
                continue;
            }

            $fingerprint = '';
            if (preg_match(
                '/@phpstan-cwe-ignore\s+phpstanCwe\.cwe95\[([a-f0-9]{64})\]/i',
                $comment->getText(),
                $fingerprintMatch,
            )) {
                $fingerprint = strtolower($fingerprintMatch[1]);
            }

            $reason = '';
            if (preg_match('/@phpstan-cwe-ignore[^\r\n]*\(([^)]*)\)/', $comment->getText(), $reasonMatch)) {
                $reason = trim($reasonMatch[1]);
            }

            return [
                'file' => $scope->getFile(),
                'line' => $comment->getStartLine(),
                'startOffset' => $node->getStartTokenPos(),
                'endOffset' => $node->getEndTokenPos(),
                'fingerprint' => $fingerprint,
                'reason' => $reason,
            ];
        }

        return null;
    }
}
