<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe79\Cwe79Rule;

covers(Cwe79Rule::class);

it('keeps output value facts separate from callable return facts', function (array $event, array $variables, array $expected): void {
    $facts = invade(new Cwe79Rule())->resolveInput($event + ['request' => false, 'variables' => []], $variables);

    expect($facts)->toBe($expected);
})->with([
    'arrow assignment' => [
        ['kind' => 'assignment', 'isArrow' => true, 'request' => true],
        [],
        ['value' => false, 'callable' => true],
    ],
    'unknown callback' => [
        ['kind' => 'sink', 'calledVariables' => ['callback']],
        [],
        ['value' => false, 'callable' => false],
    ],
    'copy of unknown callback' => [
        ['kind' => 'assignment', 'copiedVariable' => 'callback'],
        [],
        ['value' => false, 'callable' => false],
    ],
    'copy of known callback' => [
        ['kind' => 'assignment', 'copiedVariable' => 'callback'],
        ['callback' => ['value' => false, 'callable' => true]],
        ['value' => false, 'callable' => true],
    ],
    'assignment of a callback result' => [
        ['kind' => 'assignment', 'calledVariables' => ['callback']],
        ['callback' => ['value' => false, 'callable' => true]],
        ['value' => true, 'callable' => false],
    ],
]);
