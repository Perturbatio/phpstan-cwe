<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe89;

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
    // @pest-mutate-ignore
    private const int STATUS_STATIC = 0;
    // @pest-mutate-ignore
    private const int STATUS_UNKNOWN = 1;
    // @pest-mutate-ignore
    private const int STATUS_REQUEST = 2;

    public function __construct(private readonly int $minProbability = 0)
    {
        CweReport::isEnabled($minProbability, self::getRequestProbability());
    }

    public static function getRequestProbability(): int
    {
        return 80;
    }

    public static function getUnknownProbability(): int
    {
        return 45;
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
        $events = array_filter($events, static fn (?array $event): bool => $event !== null);
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
            if ($status === self::STATUS_STATIC) {
                continue;
            }

            $isKnownRequest = $status === self::STATUS_REQUEST;
            $probability = $isKnownRequest ? self::getRequestProbability() : self::getUnknownProbability();
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
                tip: 'If you use wrap() for an SQL identifier, verify that PHPStan knows the argument is a string and the receiver is Illuminate\Database\Grammar or a subclass. Add or correct parameter types where needed. A string type alone does not make raw SQL safe. Use bound parameters for values.',
            );
        }

        return $reports;
    }

    /**
     * Status: 0 means static, 1 means unknown, 2 means request input.
     *
     * @param LaravelSqlEvent $event
     * @param array<string, int> $variables
     */
    private function resolveStatus(array $event, array $variables): int
    {
        $status = $event['request'] ? self::STATUS_REQUEST : ($event['unknown'] ? self::STATUS_UNKNOWN : self::STATUS_STATIC);
        foreach ($event['variables'] as $variable) {
            $status = max($status, $variables[$variable] ?? self::STATUS_UNKNOWN);
        }

        return $status;
    }
}
