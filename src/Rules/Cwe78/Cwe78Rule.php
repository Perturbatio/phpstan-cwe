<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe78;

use Perturbatio\PhpstanCwe\CweReport;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * @phpstan-import-type Cwe78Event from Cwe78Collector
 * @phpstan-import-type Cwe78IgnoreEvent from Cwe78IgnoreCollector
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
        $reports = [];
        // The collector groups events by file. Check each file in source order
        /** @var array<string, list<Cwe78Event|null>> $eventsByFile */
        $eventsByFile = $node->get(Cwe78Collector::class);
        foreach ($eventsByFile as $file => $events) {
            $reports = array_merge($reports, $this->reportsForFile($file, $events));
        }

        // An ignore must include a reason with at least two words
        /** @var array<string, list<Cwe78IgnoreEvent|null>> $ignoresByFile */
        $ignoresByFile = $node->get(Cwe78IgnoreCollector::class);
        foreach ($ignoresByFile as $file => $events) {
            foreach ($events as $event) {
                if ($event === null || $this->wordCount($event['reason']) > 1) {
                    continue;
                }

                $reports[] = RuleErrorBuilder::message(
                    'CWE-78 ignore requires a reason with at least two words.',
                )
                    ->identifier('phpstanCwe.ignoreReason')
                    ->file($file)
                    ->line($event['line'])
                    ->build();
            }
        }

        return $reports;
    }

    /**
     * @param list<Cwe78Event|null> $events
     * @return list<IdentifierRuleError>
     */
    private function reportsForFile(string $file, array $events): array
    {
        // Ignore missing events and sort the rest so assignments are known first
        $events = array_filter($events, static fn (?array $event): bool => $event !== null);
        usort($events, static fn (array $left, array $right): int => $left['offset'] <=> $right['offset']);

        // Keep facts separate for each function or file scope
        $variablesByScope = [];
        $reports = [];
        foreach ($events as $event) {
            $variablesByScope[$event['scope']] ??= [];
            $variables = $variablesByScope[$event['scope']];

            if ($event['kind'] === 'assignment') {
                // Save facts for later uses of this variable
                $variablesByScope[$event['scope']][$event['variable']] = $this->resolveFacts($event, $variables, true);
                continue;
            }

            // A command may be unsafe even when no request source is known
            $facts = $this->resolveFacts($event, $variables, false);
            [$severity, $probability, $reason] = $this->rating($facts);
            if (!CweReport::isEnabled($this->minProbability, $probability)) {
                continue;
            }

            $reports[] = CweReport::make(78, $reason, $severity, $probability, $file, $event['line']);
        }

        return $reports;
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

    private function wordCount(string $reason): int
    {
        // Count words made from letters or numbers, including Unicode text
        preg_match_all('/[\p{L}\p{N}]+/u', $reason, $matches);

        return count($matches[0]);
    }
}
