<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

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
 * @phpstan-import-type Cwe95Event from Cwe95Collector
 * @phpstan-import-type Cwe95FlowEvent from Cwe95Collector
 * @phpstan-import-type CweIgnoreEvent from CweIgnoreCollector
 * @implements Rule<CollectedDataNode>
 */
final class Cwe95Rule implements Rule
{
    private const string SEVERITY_HIGH = 'high';
    private const string SEVERITY_MEDIUM = 'medium';
    private const string SEVERITY_LOW = 'low';

    public function __construct(private readonly int $minProbability = 0)
    {
        CweReport::isEnabled($minProbability, self::getLowestProbability());
    }

    public static function getDirectInputProbability(): int
    {
        return 95;
    }

    public static function getAssignedInputProbability(): int
    {
        return 90;
    }

    public static function getUnknownValueProbability(): int
    {
        return 60;
    }

    public static function getLowestProbability(): int
    {
        return 30;
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $reports = [];
        /** @var array<string, list<Cwe95Event|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe95Collector::class);
        $ignoresByFile = CweIgnoreCollector::fromNode($node, 95);

        foreach ($eventsByFile as $file => $events) {
            $reports = array_merge(
                $reports,
                $this->reportsForFile($file, $events, $ignoresByFile[$file] ?? []),
            );
        }

        foreach ($ignoresByFile as $file => $ignores) {
            if (array_key_exists($file, $eventsByFile)) {
                continue;
            }
            $reports = array_merge($reports, $this->reportsForFile($file, [], $ignores));
        }

        return $reports;
    }

    /**
     * @param list<Cwe95Event|null> $events
     * @param list<CweIgnoreEvent> $ignores
     * @return list<IdentifierRuleError>
     */
    private function reportsForFile(string $file, array $events, array $ignores): array
    {
        $reports = [];
        $ignoreSet = new CweIgnoreSet(95, $file, $ignores);

        foreach (LocalAssignmentFlow::sinks($this->isolateClosureScopes($events), $this->resolveFacts(...)) as [$event, $facts]) {
            $sources = $facts['sources'];
            sort($sources);
            $fingerprint = CweFingerprint::make(95, [
                $file,
                $event['scope'],
                $event['expression'],
                implode('|', $sources),
            ]);
            if ($ignoreSet->suppressesAt($fingerprint, $event['offset'])) {
                continue;
            }
            [$severity, $probability, $reason] = $this->rating($facts, $event['sources'] !== []);
            if (!CweReport::isEnabled($this->minProbability, $probability)) {
                continue;
            }

            $reports[] = CweReport::make(
                95,
                $reason,
                $severity,
                $probability,
                $file,
                $event['line'],
                tip: CweIgnoreSet::tip(95, $fingerprint, 'the evaluated code'),
                fingerprint: $fingerprint,
            );
        }

        return array_merge($reports, $ignoreSet->reports());
    }

    /**
     * @param list<Cwe95Event|null> $events
     * @return list<Cwe95FlowEvent>
     */
    private function isolateClosureScopes(array $events): array
    {
        $closures = [];
        $flowEvents = [];
        foreach ($events as $event) {
            if ($event === null) {
                continue;
            }
            if ($event['kind'] === 'scope') {
                $closures[$event['offset']] = $event;
            } else {
                $flowEvents[] = $event;
            }
        }
        ksort($closures);

        foreach ($flowEvents as $index => $event) {
            $closureNumber = 0;
            $closureScope = $event['scope'];
            $scopeOffset = $event['kind'] === 'assignment' ? $event['startOffset'] : $event['offset'];
            foreach ($closures as $closure) {
                $closureNumber++;
                if ($closure['scope'] === $event['scope']
                    && $closure['offset'] < $scopeOffset
                    && $scopeOffset < $closure['endOffset']
                ) {
                    // Use source order, not token positions, in the fingerprint.
                    $closureScope = $event['scope'] . '::closure' . $closureNumber;
                }
            }
            $flowEvents[$index]['scope'] = $closureScope;
        }

        return $flowEvents;
    }

    /**
     * @param Cwe95FlowEvent $event
     * @param array<string, array{sources: list<string>, unknown: bool, throughAssignment: bool}> $variables
     * @return array{sources: list<string>, unknown: bool, throughAssignment: bool}
     */
    private function resolveFacts(array $event, array $variables, bool $isAssignment): array
    {
        $sources = $event['sources'];
        $unknown = $event['unknown'];
        $throughAssignment = false;
        foreach ($event['variables'] as $variable) {
            $variableFacts = $variables[$variable] ?? null;
            if ($variableFacts === null) {
                $unknown = true;
                continue;
            }

            $sources = array_values(array_unique(array_merge($sources, $variableFacts['sources'])));
            $unknown = $unknown || $variableFacts['unknown'];
            if ($variableFacts['sources'] !== []) {
                $throughAssignment = true;
            }
            $throughAssignment = $throughAssignment || $variableFacts['throughAssignment'];
        }

        if ($isAssignment && $sources !== []) {
            $throughAssignment = true;
        }

        return [
            'sources' => $sources,
            'unknown' => $unknown,
            'throughAssignment' => $throughAssignment,
        ];
    }

    /**
     * @param array{sources: list<string>, unknown: bool, throughAssignment: bool} $facts
     * @return array{string, int, string}
     */
    private function rating(array $facts, bool $hasDirectInput): array
    {
        if ($facts['sources'] !== []) {
            if ($facts['throughAssignment'] && !$hasDirectInput) {
                return [
                    self::SEVERITY_HIGH,
                    self::getAssignedInputProbability(),
                    'External input reaches eval() through a local assignment. Do not evaluate external input.',
                ];
            }

            return [
                self::SEVERITY_HIGH,
                self::getDirectInputProbability(),
                'External input is passed to eval(). Do not evaluate external input.',
            ];
        }

        if ($facts['unknown']) {
            return [
                self::SEVERITY_MEDIUM,
                self::getUnknownValueProbability(),
                'The value passed to eval() is not known to be static. Review its source and avoid dynamic evaluation.',
            ];
        }

        return [
            self::SEVERITY_LOW,
            self::getLowestProbability(),
            'The code calls eval(), but no external input is known. Review the evaluated code and its source.',
        ];
    }
}
