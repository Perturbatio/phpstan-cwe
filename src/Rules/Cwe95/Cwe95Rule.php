<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

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
 * @phpstan-import-type Cwe95Event from Cwe95Collector
 * @phpstan-import-type Cwe95FlowEvent from Cwe95Collector
 * @phpstan-type Cwe95Facts array{sources: list<string>, unknown: bool, throughAssignment: bool, unknownMethodCalls?: non-empty-list<string>}
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
        /** @var array<string, list<Cwe95Event|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe95Collector::class);
        return CweFileReports::forFiles(
            95,
            $this->minProbability,
            'the evaluated code',
            array_keys($eventsByFile),
            CweIgnoreCollector::fromNode($node, 95),
            fn (string $file, CweFileReports $reports) => $this->reportsForFile($file, $eventsByFile[$file] ?? [], $reports),
        );
    }

    /**
     * Make CWE-95 reports for the events in one file.
     *
     * @param list<Cwe95Event|null> $events
     */
    private function reportsForFile(string $file, array $events, CweFileReports $reports): void
    {
        $flowEvents = [];
        foreach (ClosureScopeIsolation::isolate($events) as [$event, $scope]) {
            $event['scope'] = $scope;
            $flowEvents[] = $event;
        }

        foreach (LocalAssignmentFlow::sinks($flowEvents, $this->resolveFacts(...)) as [$event, $facts]) {
            $sources = $facts['sources'];
            sort($sources);
            $unknownMethodCalls = $facts['unknownMethodCalls'] ?? [];
            sort($unknownMethodCalls);
            $fingerprint = CweFingerprint::make(95, [
                $file,
                $event['scope'],
                $event['expression'],
                implode('|', $sources),
                ...$unknownMethodCalls,
            ]);
            [$severity, $probability, $reason] = $this->rating($facts, $event['sources'] !== []);
            $reports->add(
                $fingerprint,
                $event['offset'],
                $event['line'],
                $reason,
                $severity,
                $probability,
            );
        }
    }

    /**
     * @param Cwe95FlowEvent $event
     * @param array<string, Cwe95Facts> $variables
     * @return Cwe95Facts
     */
    private function resolveFacts(array $event, array $variables, bool $isAssignment): array
    {
        $sources = $event['sources'];
        $unknown = $event['unknown'];
        $throughAssignment = false;
        $unknownMethodCalls = $event['kind'] === 'assignment' && isset($event['unknownMethodCall'])
            ? [$event['unknownMethodCall']]
            : [];
        foreach ($event['variables'] as $variable) {
            $variableFacts = $variables[$variable] ?? null;
            if ($variableFacts === null) {
                $unknown = true;
                continue;
            }

            $sources = array_values(array_unique(array_merge($sources, $variableFacts['sources'])));
            $unknownMethodCalls = array_values(array_unique(array_merge($unknownMethodCalls, $variableFacts['unknownMethodCalls'] ?? [])));
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
            ...($unknownMethodCalls === [] ? [] : ['unknownMethodCalls' => $unknownMethodCalls]),
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
