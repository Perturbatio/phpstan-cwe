<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\LocalAssignmentFlow;

covers(LocalAssignmentFlow::class);

it('sorts events and replaces local facts without changing copies or other scopes', function (): void {
    $assignment = static fn (int $offset, string $variable, bool $request, array $variables = [], string $scope = 'file'): array => [
        'kind' => 'assignment', 'scope' => $scope, 'offset' => $offset,
        'variable' => $variable, 'request' => $request, 'variables' => $variables,
    ];
    $sink = static fn (int $offset, array $variables, string $scope = 'file'): array => [
        'kind' => 'sink', 'scope' => $scope, 'offset' => $offset,
        'request' => false, 'variables' => $variables,
    ];
    $events = [
        $sink(60, ['copy']),
        $assignment(10, 'value', true),
        null,
        $sink(5, ['value']),
        $assignment(20, 'copy', false, ['value']),
        $assignment(30, 'value', false),
        $sink(40, ['value']),
        $sink(50, ['copy'], 'function'),
    ];
    $resolved = iterator_to_array(LocalAssignmentFlow::sinks(
        $events,
        static function (array $event, array $variables, bool $isAssignment): bool {
            expect($isAssignment)->toBe($event['kind'] === 'assignment');

            return $event['request'] || in_array(
                true,
                array_map(static fn (string $variable): bool => $variables[$variable] ?? false, $event['variables']),
                true,
            );
        },
    ));

    expect(array_column(array_column($resolved, 0), 'offset'))->toBe([5, 40, 50, 60])
        ->and(array_column($resolved, 1))->toBe([false, false, false, true])
        ->and(iterator_to_array(LocalAssignmentFlow::sinks([], static fn (): bool => false)))->toBe([]);
});
