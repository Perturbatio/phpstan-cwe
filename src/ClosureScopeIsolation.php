<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

final class ClosureScopeIsolation
{
    /**
     * Process events from one file. Use the start of an assignment to find its
     * scope, even when its value contains a closure. Closure numbers use source
     * order so that token position changes do not change finding fingerprints.
     * Return each event with its scope name. This does not follow captured
     * values into a closure. A sink can use a separate position for its scope.
     *
     * @template TAssignment of array{kind: 'assignment', scope: string, offset: int, startOffset: int, ...}
     * @template TSink of array{kind: 'sink', scope: string, offset: int, ...}
     * @param list<TAssignment|TSink|array{kind: 'scope', scope: string, offset: int, endOffset: int, ...}|null> $events
     * @param (callable(TSink): int)|null $sinkScopeOffset
     * @return list<array{TAssignment|TSink, string}>
     */
    public static function isolate(array $events, ?callable $sinkScopeOffset = null): array
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

        $scopedEvents = [];
        foreach ($flowEvents as $event) {
            $closureNumber = 0;
            $closureScope = $event['scope'];
            $scopeOffset = $event['kind'] === 'assignment'
                ? $event['startOffset']
                : ($sinkScopeOffset === null ? $event['offset'] : $sinkScopeOffset($event));
            foreach ($closures as $closure) {
                $closureNumber++;
                if ($closure['scope'] === $event['scope']
                    && $closure['offset'] < $scopeOffset
                    && $scopeOffset < $closure['endOffset']
                ) {
                    $closureScope = $event['scope'] . '::closure' . $closureNumber;
                }
            }
            $scopedEvents[] = [$event, $closureScope];
        }

        return $scopedEvents;
    }
}
