<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules;

use Perturbatio\PhpstanCwe\CweReport;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;

/**
 * @phpstan-import-type LaravelSqlEvent from Cwe89LaravelCollector
 * @implements Rule<CollectedDataNode>
 */
final class Cwe89LaravelRule implements Rule
{
    private const string SEVERITY = 'high';
    private const int REQUEST_PROBABILITY = 80;
    private const int UNKNOWN_PROBABILITY = 45;

    public function __construct(private readonly int $minProbability = 0)
    {
        CweReport::isEnabled($minProbability, self::REQUEST_PROBABILITY);
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $reports = [];
        foreach ($node->get(Cwe89LaravelCollector::class) as $file => $events) {
            $reports = array_merge($reports, $this->reportsForFile($file, $events));
        }

        return $reports;
    }

    /**
     * @param list<LaravelSqlEvent|null> $events
     * @return list<\PHPStan\Rules\IdentifierRuleError>
     */
    private function reportsForFile(string $file, array $events): array
    {
        $events = array_values(array_filter($events, static fn (?array $event): bool => $event !== null));
        usort($events, static fn (array $left, array $right): int => $left['offset'] <=> $right['offset']);

        $variablesByScope = [];
        $reports = [];
        foreach ($events as $event) {
            $scope = $event['scope'];
            $variablesByScope[$scope] ??= [];
            $variables = $variablesByScope[$scope];
            $status = $this->resolveStatus($event, $variables);

            if ($event['kind'] === 'assignment') {
                $variablesByScope[$scope][$event['variable']] = $status;
                continue;
            }
            if ($status === 0) {
                continue;
            }

            $isKnownRequest = ($status & 2) !== 0;
            $probability = $isKnownRequest ? self::REQUEST_PROBABILITY : self::UNKNOWN_PROBABILITY;
            if (!CweReport::isEnabled($this->minProbability, $probability)) {
                continue;
            }

            $reason = $isKnownRequest
                ? 'Request input is used in Laravel raw SQL. Use a bound parameter.'
                : 'Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter.';
            $reports[] = CweReport::make(
                89,
                $reason,
                self::SEVERITY,
                $probability,
                $file,
                $event['line'],
            );
        }

        return $reports;
    }

    /**
     * Status bits: 1 means unknown source, 2 means known request input.
     *
     * @param LaravelSqlEvent $event
     * @param array<string, int> $variables
     */
    private function resolveStatus(array $event, array $variables): int
    {
        if (!$event['dynamic']) {
            return 0;
        }

        $status = ($event['request'] ? 2 : 0) | ($event['unknown'] ? 1 : 0);
        foreach ($event['variables'] as $variable) {
            $status |= $variables[$variable] ?? 1;
        }

        return $status;
    }
}
