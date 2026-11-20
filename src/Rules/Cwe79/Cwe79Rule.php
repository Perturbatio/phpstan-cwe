<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\ClosureScopeIsolation;
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
 * @phpstan-import-type HtmlFlowEvent from Cwe79Collector
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
        $flowEvents = [];
        foreach (ClosureScopeIsolation::isolate($events, static fn (array $sink): int => $sink['startOffset']) as [$event, $scope]) {
            $event['scope'] = $scope;
            $flowEvents[] = $event;
        }

        foreach (LocalAssignmentFlow::sinks($flowEvents, $this->resolveInput(...)) as [$event, $facts]) {
            if (!$facts['value']) {
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
     * @param HtmlFlowEvent $event
     * @param array<string, array{value: bool, callable: bool}> $variables
     * @return array{value: bool, callable: bool}
     */
    private function resolveInput(array $event, array $variables): array
    {
        $request = $event['request'];
        foreach ($event['variables'] as $variable) {
            $request = $request || ($variables[$variable]['value'] ?? false);
        }
        foreach ($event['calledVariables'] ?? [] as $variable) {
            $request = $request || ($variables[$variable]['callable'] ?? false);
        }

        if ($event['kind'] === 'assignment' && ($event['isArrow'] ?? false)) {
            return ['value' => false, 'callable' => $request];
        }

        return [
            'value' => $request,
            'callable' => $event['kind'] === 'assignment' && isset($event['copiedVariable'])
                ? ($variables[$event['copiedVariable']]['callable'] ?? false)
                : false,
        ];
    }
}
