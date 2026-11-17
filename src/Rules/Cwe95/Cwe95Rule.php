<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\LocalAssignmentFlow;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * @phpstan-import-type Cwe95Event from Cwe95Collector
 * @phpstan-import-type Cwe95FlowEvent from Cwe95Collector
 * @phpstan-import-type Cwe95IgnoreEvent from Cwe95IgnoreCollector
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
        /** @var array<string, list<Cwe95IgnoreEvent|null>> $ignoresByFile */
        $ignoresByFile = $node->get(Cwe95IgnoreCollector::class);

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
     * @param list<Cwe95IgnoreEvent|null> $ignores
     * @return list<IdentifierRuleError>
     */
    private function reportsForFile(string $file, array $events, array $ignores): array
    {
        $reports = [];
        $validIgnores = [];
        $matchedIgnores = [];

        foreach ($ignores as $index => $ignore) {
            if ($ignore === null) {
                continue;
            }

            $hasValidFingerprint = preg_match('/^[a-f0-9]{64}$/', $ignore['fingerprint']) === 1;
            $hasValidReason = $this->wordCount($ignore['reason']) >= 2;
            if (!$hasValidFingerprint) {
                $reports[] = RuleErrorBuilder::message(
                    'CWE-95 ignore must include a 64-character fingerprint.',
                )
                    ->identifier('phpstanCwe.ignoreFingerprint')
                    ->file($file)
                    ->line($ignore['line'])
                    ->build();
            }
            if (!$hasValidReason) {
                $reports[] = RuleErrorBuilder::message(
                    'CWE-95 ignore requires a reason with at least two words.',
                )
                    ->identifier('phpstanCwe.ignoreReason')
                    ->file($file)
                    ->line($ignore['line'])
                    ->build();
            }
            if ($hasValidFingerprint && $hasValidReason) {
                $validIgnores[$index] = true;
            }
        }

        foreach (LocalAssignmentFlow::sinks($this->isolateClosureScopes($events), $this->resolveFacts(...)) as [$event, $facts]) {
            $fingerprint = Cwe95Fingerprint::make(
                $file,
                $event['scope'],
                $event['expression'],
                $facts['sources'],
            );
            $isIgnored = false;
            foreach ($ignores as $index => $ignore) {
                if ($ignore === null || ($matchedIgnores[$index] ?? false)
                    || $ignore['fingerprint'] !== $fingerprint
                    || $event['offset'] < $ignore['startOffset']
                    || $event['offset'] > $ignore['endOffset']
                ) {
                    continue;
                }

                $matchedIgnores[$index] = true;
                $isIgnored = $isIgnored || ($validIgnores[$index] ?? false);
            }
            if ($isIgnored) {
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
                tip: sprintf(
                    'Only ignore this finding if you have checked that the evaluated code is safe. Give a reason with at least two words: // @phpstan-cwe-ignore phpstanCwe.cwe95[%s] (<reason>)',
                    $fingerprint,
                ),
                fingerprint: $fingerprint,
            );
        }

        foreach ($ignores as $index => $ignore) {
            if ($ignore === null || !preg_match('/^[a-f0-9]{64}$/', $ignore['fingerprint'])) {
                continue;
            }
            if ($matchedIgnores[$index] ?? false) {
                continue;
            }

            $reports[] = RuleErrorBuilder::message(
                'CWE-95 ignore fingerprint does not match a finding. Review or remove this ignore.',
            )
                ->identifier('phpstanCwe.ignoreUnmatched')
                ->file($file)
                ->line($ignore['line'])
                ->build();
        }

        return $reports;
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

    private function wordCount(string $reason): int
    {
        preg_match_all('/[\p{L}\p{N}]+/u', $reason, $matches);

        return count($matches[0]);
    }
}
