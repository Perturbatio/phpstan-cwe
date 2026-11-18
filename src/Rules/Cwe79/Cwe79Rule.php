<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use Perturbatio\PhpstanCwe\LocalAssignmentFlow;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;

/**
 * @phpstan-import-type HtmlEvent from Cwe79Collector
 * @phpstan-import-type CweIgnoreEvent from CweIgnoreCollector
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
        $reports = [];
        /** @var array<string, list<HtmlEvent|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe79Collector::class);
        $ignoresByFile = CweIgnoreCollector::fromNode($node, 79);
        foreach ($eventsByFile as $file => $events) {
            $reports = array_merge($reports, $this->reportsForFile($file, $events, $ignoresByFile[$file] ?? []));
        }
        foreach (array_diff_key($ignoresByFile, $eventsByFile) as $file => $ignores) {
            $reports = array_merge($reports, $this->reportsForFile($file, [], $ignores));
        }

        return $reports;
    }

    /**
     * @param list<HtmlEvent|null> $events
     * @param list<CweIgnoreEvent> $ignores
     * @return list<IdentifierRuleError>
     */
    private function reportsForFile(string $file, array $events, array $ignores): array
    {
        $reports = [];
        $ignoreSet = new CweIgnoreSet(79, $file, $ignores);
        foreach (LocalAssignmentFlow::sinks($events, $this->resolveInput(...)) as [$event, $request]) {
            if (!$request) {
                continue;
            }

            $fingerprint = CweFingerprint::make(79, [$file, $event['scope'], $event['expression']]);
            if ($ignoreSet->suppressesAt($fingerprint, $event['offset'])
                || !CweReport::isEnabled($this->minProbability, self::getProbability())
            ) {
                continue;
            }

            $reports[] = CweReport::make(
                79,
                'Request input is sent to HTML without an HTML escape call.',
                self::SEVERITY,
                self::getProbability(),
                $file,
                $event['line'],
                tip: CweIgnoreSet::tip(79, $fingerprint, 'the printed value'),
                fingerprint: $fingerprint,
            );
        }

        return array_merge($reports, $ignoreSet->reports());
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
