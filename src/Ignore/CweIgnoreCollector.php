<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Ignore;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Node\CollectedDataNode;

/**
 * Collect comments with a fingerprint after the CWE identifier.
 * Each rule reads only the events for its own CWE number.
 *
 * @phpstan-type CweIgnoreEvent array{
 *     cwe: int,
 *     file: string,
 *     line: int,
 *     startOffset: int,
 *     endOffset: int,
 *     startLine: int,
 *     endLine: int,
 *     fingerprint: string,
 *     reason: string
 * }
 * @implements Collector<Node, list<CweIgnoreEvent>|null>
 */
final class CweIgnoreCollector implements Collector
{
    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return list<CweIgnoreEvent>|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (!$node instanceof Stmt) {
            return null;
        }

        $events = [];
        foreach ($node->getComments() as $comment) {
            $text = $comment->getText();
            preg_match_all(
                '/@phpstan-ignore\s+phpstanCwe\.cwe(\d+)\.([a-z0-9.]+)(?=[ \t(,]|\*\/|[\r\n]|\z)(?:[ \t]*\(([^)\r\n]*)\))?/i',
                $text,
                $matches,
                PREG_SET_ORDER | PREG_OFFSET_CAPTURE,
            );
            foreach ($matches as $match) {
                $events[] = [
                    'cwe' => (int) $match[1][0],
                    'file' => $scope->getFile(),
                    'line' => $comment->getStartLine() + substr_count($text, "\n", 0, $match[0][1]),
                    'startOffset' => $node->getStartTokenPos(),
                    'endOffset' => $node->getEndTokenPos(),
                    'startLine' => $node->getStartLine(),
                    'endLine' => $node->getEndLine(),
                    'fingerprint' => strtolower($match[2][0]),
                    'reason' => trim($match[3][0] ?? ''),
                ];
            }
        }

        return $events === [] ? null : $events;
    }

    /**
     * @param array<string, list<list<CweIgnoreEvent>|null>> $collected
     * @return array<string, list<CweIgnoreEvent>>
     */
    public static function forCwe(array $collected, int $cwe): array
    {
        $result = [];
        foreach ($collected as $file => $groups) {
            foreach ($groups as $events) {
                foreach ($events ?? [] as $event) {
                    if ($event['cwe'] === $cwe) {
                        $result[$file][] = $event;
                    }
                }
            }
        }

        return $result;
    }

    /** @return array<string, list<CweIgnoreEvent>> */
    public static function fromNode(CollectedDataNode $node, int $cwe): array
    {
        /** @var array<string, list<list<CweIgnoreEvent>|null>> $collected */
        $collected = $node->get(self::class);

        return self::forCwe($collected, $cwe);
    }
}
