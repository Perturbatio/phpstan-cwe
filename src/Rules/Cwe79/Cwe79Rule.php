<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\CweFileReports;
use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\LocalAssignmentFlow;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;

/**
 * @phpstan-import-type HtmlEvent from Cwe79Collector
 * @implements Rule<CollectedDataNode>
 */
final class Cwe79Rule implements Rule
{
    private const string SEVERITY = 'high';

    public function __construct(
        private readonly int $minProbability = 0,
    ) {
        // Check the minimum score when PHPStan creates this rule.
        CweReport::isEnabled($minProbability, self::getProbability());
    }

    public static function getProbability(): int
    {
        return 80;
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        /** @var array<string, list<HtmlEvent|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe79Collector::class);
        return CweFileReports::forFiles(
            79,
            $this->minProbability,
            'the printed value',
            array_keys($eventsByFile),
            CweIgnoreCollector::fromNode($node, 79),
            fn (string $file, CweFileReports $reports) => $this->reportsForFile($file, $eventsByFile[$file] ?? [], $reports),
        );
    }

    /**
     * @param list<HtmlEvent|null> $events
     */
    private function reportsForFile(string $file, array $events, CweFileReports $reports): void
    {
        foreach (LocalAssignmentFlow::sinks($events, $this->resolveInput(...)) as [$event, $request]) {
            if (!$request) {
                continue;
            }

            $fingerprint = CweFingerprint::make(79, [$file, $event['scope'], $event['expression']]);
            $reports->add(
                $fingerprint,
                $event['offset'],
                $event['line'],
                'Request input is sent to HTML without an HTML escape call.',
                self::SEVERITY,
                self::getProbability(),
            );
        }
    }

    /**
     * @param HtmlEvent $event
     * @param array<string, bool> $variables
     */
    private function resolveInput(array $event, array $variables): bool
    {
        if ($event['request']) {
            return true;
        }
        foreach ($event['variables'] as $variable) {
            if ($variables[$variable] ?? false) {
                return true;
            }
        }

        return false;
    }
}
