<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe78;

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
 * @phpstan-import-type Cwe78Event from Cwe78Collector
 * @implements Rule<CollectedDataNode>
 */
final class Cwe78Rule implements Rule
{
    public function __construct(private readonly int $minProbability = 0)
    {
        // Check the minimum score when PHPStan creates this rule
        CweReport::isEnabled($minProbability, self::getLowestProbability());
    }

    public static function getVeryHighProbability(): int
    {
        return 95;
    }

    public static function getHighProbability(): int
    {
        return 80;
    }

    public static function getMediumProbability(): int
    {
        return 60;
    }

    public static function getLowestProbability(): int
    {
        return 50;
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        /** @var array<string, list<Cwe78Event|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe78Collector::class);
        return CweFileReports::forFiles(
            78,
            $this->minProbability,
            'the command and its arguments',
            array_keys($eventsByFile),
            CweIgnoreCollector::fromNode($node, 78),
            fn (string $file, CweFileReports $reports) => $this->reportsForFile($file, $eventsByFile[$file] ?? [], $reports),
        );
    }

    /**
     * @param list<Cwe78Event|null> $events
     */
    private function reportsForFile(string $file, array $events, CweFileReports $reports): void
    {
        foreach (LocalAssignmentFlow::sinks($events, $this->resolveFacts(...)) as [$event, $facts]) {
            $fingerprint = CweFingerprint::make(78, [
                $file,
                $event['scope'],
                $event['expression'],
                sprintf('%d%d%d', $facts['request'], $facts['hasStaticText'], $facts['throughAssignment']),
            ]);
            // A command may be unsafe even when no request source is known
            [$severity, $probability, $reason] = $this->rating($facts);
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
     * @param Cwe78Event $event
     * @param array<string, array{request: bool, hasStaticText: bool, throughAssignment: bool}> $variables
     * @return array{request: bool, hasStaticText: bool, throughAssignment: bool}
     */
    private function resolveFacts(array $event, array $variables, bool $isAssignment): array
    {
        // Combine facts from this expression and variables used by it
        $request = $event['request'];
        $hasStaticText = $event['hasStaticText'];
        $throughAssignment = $isAssignment && $request;
        foreach ($event['variables'] as $variable) {
            $variableFacts = $variables[$variable] ?? null;
            if ($variableFacts === null) {
                continue;
            }
            $request = $request || $variableFacts['request'];
            $hasStaticText = $hasStaticText || $variableFacts['hasStaticText'];
            if ($variableFacts['request']) {
                $throughAssignment = $throughAssignment || $variableFacts['throughAssignment'];
            }
        }

        return [
            'request' => $request,
            'hasStaticText' => $hasStaticText,
            'throughAssignment' => $throughAssignment,
        ];
    }

    /**
     * @param array{request: bool, hasStaticText: bool, throughAssignment: bool} $facts
     * @return array{string, int, string}
     */
    private function rating(array $facts): array
    {
        // Give stronger scores when the collector finds a request source
        if (!$facts['request']) {
            return [
                'low',
                self::getLowestProbability(),
                'Review this command for external input and unsafe command arguments.',
            ];
        }

        if ($facts['throughAssignment']) {
            return [
                'medium',
                self::getMediumProbability(),
                'Request input reaches a command through a local assignment. Check the command and its arguments.',
            ];
        }

        if ($facts['hasStaticText']) {
            return [
                'high',
                self::getHighProbability(),
                'Request input changes an argument in a command with known text. Escape each argument or use a safe argument array.',
            ];
        }

        return [
            'very high',
            self::getVeryHighProbability(),
            'Request input is used as the full command. Use a fixed executable and safe arguments.',
        ];
    }
}
