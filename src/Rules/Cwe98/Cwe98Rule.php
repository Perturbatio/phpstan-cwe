<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe98;

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
 * @phpstan-import-type Cwe98Event from Cwe98Collector
 * @phpstan-import-type Cwe98Assignment from Cwe98Collector
 * @phpstan-import-type Cwe98Sink from Cwe98Collector
 * @phpstan-type Cwe98FlowEvent Cwe98Assignment|Cwe98Sink
 * @phpstan-type Cwe98ResolvedFacts array{sources: list<string>, requestProbability: int|null, unknown: bool}
 * @implements Rule<CollectedDataNode>
 */
final class Cwe98Rule implements Rule
{
    private const string SEVERITY = 'high';

    public function __construct(private readonly int $minProbability = 0)
    {
        CweReport::isEnabled($minProbability, self::getLowestProbability());
    }

    public static function getUnchangedInputProbability(): int
    {
        return 95;
    }

    public static function getTransformedInputProbability(): int
    {
        return 85;
    }

    public static function getUnknownValueProbability(): int
    {
        return 60;
    }

    public static function getNumericInputProbability(): int
    {
        return 45;
    }

    public static function getLowestProbability(): int
    {
        return self::getNumericInputProbability();
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        /** @var array<string, list<Cwe98Event|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe98Collector::class);

        return CweFileReports::forFiles(
            98,
            $this->minProbability,
            'the include filename',
            array_keys($eventsByFile),
            CweIgnoreCollector::fromNode($node, 98),
            fn (string $file, CweFileReports $reports) => $this->reportsForFile(
                $file,
                $eventsByFile[$file] ?? [],
                $reports,
            ),
        );
    }

    /**
     * Make reports for one file.
     *
     * @param list<Cwe98Event|null> $events
     */
    private function reportsForFile(string $file, array $events, CweFileReports $reports): void
    {
        $flowEvents = [];
        foreach (ClosureScopeIsolation::isolate($events, static fn (array $sink): int => $sink['startOffset']) as [$event, $isolatedScope]) {
            $event['scope'] = $isolatedScope;
            $flowEvents[] = $event;
        }

        foreach (LocalAssignmentFlow::sinks($flowEvents, $this->resolveFacts(...)) as [$event, $facts]) {
            if ($facts['sources'] === [] && !$facts['unknown']) {
                continue;
            }

            $sources = $facts['sources'];
            sort($sources);
            $probability = $facts['requestProbability'] ?? self::getUnknownValueProbability();
            $fingerprint = CweFingerprint::make(98, [
                $file,
                $event['scope'],
                $event['expression'],
                implode('|', $sources),
                sprintf('%d', $probability),
            ]);
            $reason = $facts['sources'] === []
                ? 'The include filename is dynamic and its source is unknown. Use a fixed allow-list.'
                : 'Request input is used in an include filename. Select files from a fixed allow-list.';

            $reports->add(
                $fingerprint,
                $event['offset'],
                $event['line'],
                $reason,
                self::SEVERITY,
                $probability,
            );
        }
    }

    /**
     * @param Cwe98FlowEvent $event
     * @param array<string, Cwe98ResolvedFacts> $variables
     * @return Cwe98ResolvedFacts
     */
    private function resolveFacts(array $event, array $variables, bool $isAssignment): array
    {
        $sources = $event['sources'];
        $requestProbability = $event['requestProbability'];
        $unknown = $event['unknown'];
        foreach ($event['variables'] as $name => $modifier) {
            $variableFacts = $variables[$name] ?? null;
            if ($variableFacts === null) {
                $unknown = true;
                continue;
            }

            $sources = array_values(array_unique([...$sources, ...$variableFacts['sources']]));
            if ($variableFacts['requestProbability'] !== null) {
                $variableProbability = min($modifier, $variableFacts['requestProbability']);
                $requestProbability = $requestProbability === null
                    ? $variableProbability
                    : max($requestProbability, $variableProbability);
            }
            $unknown = $unknown || $variableFacts['unknown'];
        }

        return [
            'sources' => $sources,
            'requestProbability' => $requestProbability,
            'unknown' => $unknown,
        ];
    }
}
