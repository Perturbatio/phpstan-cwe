<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe78;

use PhpParser\Node;
use PhpParser\Node\Stmt\Expression;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * @phpstan-type Cwe78IgnoreEvent array{
 *     file: string,
 *     line: int,
 *     reason: string
 * }
 * @implements Collector<Node, Cwe78IgnoreEvent|null>
 */
final class Cwe78IgnoreCollector implements Collector
{
    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return Cwe78IgnoreEvent|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node instanceof Expression) {
            return null;
        }

        foreach ($node->getComments() as $comment) {
            if (!preg_match('/@phpstan-ignore(?:-line|-next-line)?\b.*?phpstanCwe\.cwe78/s', $comment->getText())) {
                continue;
            }

            $reason = '';
            if (preg_match('/phpstanCwe\.cwe78\s*\(([^)]*)\)/', $comment->getText(), $reasonMatch)) {
                $reason = trim($reasonMatch[1]);
            }

            return [
                'file' => $scope->getFile(),
                'line' => $comment->getStartLine(),
                'reason' => $reason,
            ];
        }

        return null;
    }
}
