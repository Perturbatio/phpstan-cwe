<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

final class LocalAssignmentFlow
{
    /**
     * Process one file at a time. Keep each event's scope and source offset.
     * The resolver combines expression facts with facts from earlier assignments.
     * Return new facts for each assignment; do not keep references to source variables.
     *
     * Example: `$name = $_GET['name']; $html = '<p>' . $name; echo $html;`
     * Record two assignment events and one sink event. The resolver follows
     * `name` when it saves `html`, then follows `html` at the sink.
     *
     * Use the result in a rule:
     * foreach (LocalAssignmentFlow::sinks($events, $this->resolveFacts(...)) as [$event, $facts]) {
     *     // Check the facts and make a report at the source file and sink line.
     * }
     *
     * The resolver receives the event, the current scope's variable facts, and
     * an assignment flag. Only sinks are returned. This is a source-order scan,
     * not an analysis of branches, loops, or calls between functions.
     *
     * @template TAssignment of array{kind: 'assignment', scope: string, offset: int, variable: string}
     * @template TSink of array{kind: 'sink', scope: string, offset: int}
     * @template TFacts
     * @param list<TAssignment|TSink|null> $events
     * @param callable(TAssignment|TSink, array<string, TFacts>, bool): TFacts $resolveFacts
     * @return \Generator<int, array{TSink, TFacts}>
     */
    public static function sinks(array $events, callable $resolveFacts): \Generator
    {
        $events = array_filter($events, static fn (?array $event): bool => $event !== null);
        usort($events, static fn (array $left, array $right): int => $left['offset'] <=> $right['offset']);

        $variablesByScope = [];
        foreach ($events as $event) {
            $variables = $variablesByScope[$event['scope']] ?? [];
            $isAssignment = $event['kind'] === 'assignment';
            $facts = $resolveFacts($event, $variables, $isAssignment);
            if ($event['kind'] === 'assignment') {
                $variablesByScope[$event['scope']][$event['variable']] = $facts;
                continue;
            }

            yield [$event, $facts];
        }
    }
}
