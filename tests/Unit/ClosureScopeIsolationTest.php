<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\ClosureScopeIsolation;

covers(ClosureScopeIsolation::class);

it('isolates nested and sibling closures in source order without changing other event facts', function (): void {
    $events = [
        ['kind' => 'scope', 'scope' => 'run', 'offset' => 40, 'endOffset' => 50],
        ['kind' => 'scope', 'scope' => 'run', 'offset' => 20, 'endOffset' => 30],
        ['kind' => 'scope', 'scope' => 'run', 'offset' => 10, 'endOffset' => 35],
        null,
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 10, 'line' => 1],
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 15, 'line' => 2],
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 25, 'line' => 3],
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 30, 'line' => 4],
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 45, 'line' => 5],
        ['kind' => 'sink', 'scope' => 'run', 'offset' => 50, 'line' => 6],
        ['kind' => 'sink', 'scope' => 'other', 'offset' => 25, 'line' => 7],
    ];

    expect(ClosureScopeIsolation::isolate($events))->toBe([
        [$events[4], 'run'],
        [$events[5], 'run::closure1'],
        [$events[6], 'run::closure2'],
        [$events[7], 'run::closure1'],
        [$events[8], 'run::closure3'],
        [$events[9], 'run'],
        [$events[10], 'other'],
    ])->and(ClosureScopeIsolation::isolate([]))->toBe([]);
});

it('uses the assignment start rather than its end to select a scope', function (): void {
    $events = [
        ['kind' => 'scope', 'scope' => 'run', 'offset' => 10, 'endOffset' => 30],
        ['kind' => 'assignment', 'scope' => 'run', 'startOffset' => 5, 'offset' => 30, 'variable' => 'callback'],
        ['kind' => 'assignment', 'scope' => 'run', 'startOffset' => 15, 'offset' => 29, 'variable' => 'value'],
        ['kind' => 'assignment', 'scope' => 'other', 'startOffset' => 15, 'offset' => 29, 'variable' => 'value'],
    ];

    expect(ClosureScopeIsolation::isolate($events))->toBe([
        [$events[1], 'run'],
        [$events[2], 'run::closure1'],
        [$events[3], 'other'],
    ]);
});

it('uses a sink start when its end is at a closure boundary', function (): void {
    $events = [
        ['kind' => 'scope', 'scope' => 'run', 'offset' => 10, 'endOffset' => 30],
        ['kind' => 'sink', 'scope' => 'run', 'startOffset' => 20, 'offset' => 30],
        ['kind' => 'sink', 'scope' => 'run', 'startOffset' => 30, 'offset' => 30],
    ];

    expect(ClosureScopeIsolation::isolate($events, static fn (array $sink): int => $sink['startOffset']))->toBe([
        [$events[1], 'run::closure1'],
        [$events[2], 'run'],
    ]);
});
