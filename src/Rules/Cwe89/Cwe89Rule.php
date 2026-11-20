<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe89;

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
 * @phpstan-import-type LaravelSqlEvent from Cwe89LaravelCollector
 * @phpstan-import-type DirectSqlSink from Cwe89Collector
 * @implements Rule<CollectedDataNode>
 */
final class Cwe89Rule implements Rule
{
    private const string SEVERITY = 'high';
    private const string WRAP_TIP = 'If you use wrap() for an SQL identifier, verify that PHPStan knows the argument is a string and the receiver is Illuminate\\Database\\Grammar or a subclass. Add or correct parameter types where needed. A string type alone does not make raw SQL safe. Use bound parameters for values.';
    // @pest-mutate-ignore
    private const int STATUS_STATIC = 0;
    // @pest-mutate-ignore
    private const int STATUS_UNKNOWN = 1;
    // @pest-mutate-ignore
    private const int STATUS_REQUEST = 2;

    public function __construct(private readonly int $minProbability = 0)
    {
        // Check the minimum score when PHPStan creates this rule
        CweReport::isEnabled($minProbability, self::getUnknownProbability());
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
        /** @var array<string, list<LaravelSqlEvent|null>> $laravelByFile */
        $laravelByFile = $node->get(Cwe89LaravelCollector::class);
        /** @var array<string, list<DirectSqlSink|null>> $directByFile */
        $directByFile = $node->get(Cwe89Collector::class);
        return CweFileReports::forFiles(
            89,
            $this->minProbability,
            'the SQL text',
            [...array_keys($laravelByFile), ...array_keys($directByFile)],
            CweIgnoreCollector::fromNode($node, 89),
            fn (string $file, CweFileReports $reports) => $this->reportsForFile(
                $file,
                $laravelByFile[$file] ?? [],
                $directByFile[$file] ?? [],
                $reports,
            ),
        );
    }

    /**
     * Direct and Laravel findings share one annotation set because both rules use CWE-89 annotations.
     *
     * @param list<LaravelSqlEvent|null> $laravelEvents
     * @param list<DirectSqlSink|null> $directEvents
     */
    private function reportsForFile(string $file, array $laravelEvents, array $directEvents, CweFileReports $reports): void
    {
        foreach ($directEvents as $event) {
            if ($event === null) {
                continue;
            }

            $fingerprint = CweFingerprint::make(89, [$file, $event['scope'], 'direct', $event['expression']]);
            $reports->add(
                $fingerprint,
                $event['offset'],
                $event['line'],
                'Request input is used in a SQL query. Use a bound parameter.',
                self::SEVERITY,
                self::getRequestProbability(),
            );
        }

        foreach (LocalAssignmentFlow::sinks($laravelEvents, $this->resolveStatus(...)) as [$event, $status]) {
            if ($status === self::STATUS_STATIC) {
                continue;
            }

            $isKnownRequest = $status === self::STATUS_REQUEST;
            $fingerprint = CweFingerprint::make(89, [$file, $event['scope'], 'laravel', $event['expression'], sprintf('%d', $status)]);
            // Unknown dynamic values get a lower score than known request data
            $reports->add(
                $fingerprint,
                $event['offset'],
                $event['line'],
                $isKnownRequest
                    ? 'Request input is used in Laravel raw SQL. Use a bound parameter.'
                    : 'Warning: The source of a dynamic value in Laravel raw SQL is unknown. Use a bound parameter.',
                self::SEVERITY,
                $isKnownRequest ? self::getRequestProbability() : self::getUnknownProbability(),
                self::WRAP_TIP,
            );
        }
    }

    /**
     * Status: 0 means static, 1 means unknown, 2 means request input.
     *
     * @param LaravelSqlEvent $event
     * @param array<string, int> $variables
     */
    private function resolveStatus(array $event, array $variables): int
    {
        // Keep the strongest known status found in the query expression
        $status = $event['request'] ? self::STATUS_REQUEST : ($event['unknown'] ? self::STATUS_UNKNOWN : self::STATUS_STATIC);
        foreach ($event['variables'] as $variable) {
            $status = max($status, $variables[$variable] ?? self::STATUS_UNKNOWN);
        }

        return $status;
    }
}
