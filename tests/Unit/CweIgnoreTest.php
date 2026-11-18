<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use PhpParser\Comment;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\Node\Stmt\Expression;
use PHPStan\Analyser\Scope;

covers(CweFingerprint::class, CweIgnoreCollector::class, CweIgnoreSet::class, ExpressionText::class);

function cweIgnoreEvent(array $changes = []): array
{
    return array_replace([
        'cwe' => 78,
        'file' => 'a.php',
        'line' => 3,
        'startOffset' => 10,
        'endOffset' => 20,
        'startLine' => 4,
        'endLine' => 6,
        'fingerprint' => str_repeat('a', 64),
        'reason' => 'checked input',
    ], $changes);
}

it('makes a stable fingerprint that depends on the CWE and each component', function (): void {
    $hash = CweFingerprint::make(78, ['a', 'b']);

    expect($hash)->toMatch('/^[a-f0-9]{64}$/')
        ->and(CweFingerprint::make(78, ['a', 'b']))->toBe($hash)
        ->and(CweFingerprint::make(79, ['a', 'b']))->not->toBe($hash)
        ->and(CweFingerprint::make(78, ['a', 'c']))->not->toBe($hash)
        ->and(CweFingerprint::make(78, ['ab', '']))->not->toBe(CweFingerprint::make(78, ['a', 'b']));
});

it('prints an expression without comments and without changing the original', function (): void {
    $expression = new FuncCall(new Name('f'), []);
    $expression->setAttribute('comments', [new Comment('// note')]);

    expect(ExpressionText::of($expression))->toBe('f()')
        ->and($expression->getComments())->toHaveCount(1);
});

it('collects ignores from statement comments with line offsets', function (): void {
    $node = new Echo_([new Variable('a')], [
        'startLine' => 5,
        'endLine' => 7,
        'startTokenPos' => 11,
        'endTokenPos' => 22,
        'comments' => [
            new Comment("// first\n// @phpstan-ignore phpstanCwe.cwe78." . strtoupper(str_repeat('a', 64)) . ' (two words)', 2),
            new Comment('/* @phpstan-ignore phpstanCwe.cwe79.abc */', 9),
            new Comment('// @phpstan-ignore phpstanCwe.cwe79'),
            new Comment('// @phpstan-ignore'),
        ],
    ]);
    $scope = $this->createStub(Scope::class);
    $scope->method('getFile')->willReturn('a.php');

    $events = (new CweIgnoreCollector())->processNode($node, $scope);

    expect($events)->toHaveCount(2)
        ->and($events[0])->toBe([
            'cwe' => 78,
            'file' => 'a.php',
            'line' => 3,
            'startOffset' => 11,
            'endOffset' => 22,
            'startLine' => 5,
            'endLine' => 7,
            'fingerprint' => str_repeat('a', 64),
            'reason' => 'two words',
        ])
        ->and($events[1]['cwe'])->toBe(79)
        ->and($events[1]['fingerprint'])->toBe('abc')
        ->and($events[1]['reason'])->toBe('');
});

it('collects nothing from expressions and statements without matching comments', function (): void {
    $scope = $this->createStub(Scope::class);
    $collector = new CweIgnoreCollector();
    $plain = new Expression(new Variable('a'), ['comments' => [new Comment('// other')]]);

    expect($collector->processNode(new Variable('a', ['comments' => [new Comment('// @phpstan-ignore phpstanCwe.cwe78.' . str_repeat('a', 64) . ' (Reviewed input)')]]), $scope))->toBeNull()
        ->and($collector->processNode($plain, $scope))->toBeNull()
        ->and($collector->getNodeType())->toBe(PhpParser\Node::class);
});

it('filters collected ignores by CWE', function (): void {
    $collected = [
        'a.php' => [[cweIgnoreEvent(), cweIgnoreEvent(['cwe' => 79])], null],
        'b.php' => [[cweIgnoreEvent(['cwe' => 79])]],
    ];

    expect(CweIgnoreCollector::forCwe($collected, 78))->toBe(['a.php' => [cweIgnoreEvent()]])
        ->and(array_keys(CweIgnoreCollector::forCwe($collected, 79)))->toBe(['a.php', 'b.php'])
        ->and(CweIgnoreCollector::forCwe($collected, 95))->toBe([]);
});

it('validates fingerprints and reasons', function (): void {
    expect(CweIgnoreSet::isValidFingerprint(str_repeat('f', 64)))->toBeTrue()
        ->and(CweIgnoreSet::isValidFingerprint(str_repeat('f', 63)))->toBeFalse()
        ->and(CweIgnoreSet::isValidFingerprint(str_repeat('f', 65)))->toBeFalse()
        ->and(CweIgnoreSet::isValidFingerprint(str_repeat('g', 64)))->toBeFalse()
        ->and(CweIgnoreSet::isValidFingerprint(str_repeat('F', 64)))->toBeFalse()
        ->and(CweIgnoreSet::hasValidReason('two words'))->toBeTrue()
        ->and(CweIgnoreSet::hasValidReason('one'))->toBeFalse()
        ->and(CweIgnoreSet::hasValidReason('...  --'))->toBeFalse()
        ->and(CweIgnoreSet::hasValidReason('éa 12'))->toBeTrue();
});

it('writes a tip with the fingerprint and the subject', function (): void {
    expect(CweIgnoreSet::tip(78, 'abc', 'the command'))->toBe(
        'Only ignore this finding if you have checked that the command is safe. Give a reason with at least two words: // @phpstan-ignore phpstanCwe.cwe78.abc (<reason>)',
    );
});

it('suppresses one finding for each ignore by token position', function (): void {
    $fingerprint = str_repeat('a', 64);
    $set = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]);

    expect($set->suppressesAt($fingerprint, 9))->toBeFalse()
        ->and($set->suppressesAt($fingerprint, 21))->toBeFalse()
        ->and($set->suppressesAt(str_repeat('b', 64), 15))->toBeFalse()
        ->and($set->suppressesAt($fingerprint, 10))->toBeTrue()
        ->and($set->suppressesAt($fingerprint, 15))->toBeFalse()
        ->and($set->reports())->toBe([]);

    $edge = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]);
    expect($edge->suppressesAt($fingerprint, 20))->toBeTrue();
});

it('suppresses by line range', function (): void {
    $fingerprint = str_repeat('a', 64);

    expect((new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]))->suppressesLines($fingerprint, 3, 5))->toBeFalse()
        ->and((new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]))->suppressesLines($fingerprint, 4, 7))->toBeFalse()
        ->and((new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]))->suppressesLines($fingerprint, 4, 6))->toBeTrue()
        ->and((new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent()]))->suppressesLines($fingerprint, 5, 5))->toBeTrue();
});

it('uses two ignores for two findings with the same fingerprint', function (): void {
    $fingerprint = str_repeat('a', 64);
    $set = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent(), cweIgnoreEvent(['line' => 8])]);

    expect($set->suppressesAt($fingerprint, 12))->toBeTrue()
        ->and($set->suppressesAt($fingerprint, 12))->toBeTrue()
        ->and($set->suppressesAt($fingerprint, 12))->toBeFalse()
        ->and($set->reports())->toBe([]);
});

it('prefers a valid ignore over an invalid ignore for the same finding', function (): void {
    $fingerprint = str_repeat('a', 64);
    $set = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent(['reason' => 'one']), cweIgnoreEvent()]);

    expect($set->suppressesAt($fingerprint, 12))->toBeTrue()
        ->and(array_map(static fn ($e) => $e->getIdentifier(), $set->reports()))->toBe(['phpstanCwe.ignoreReason', 'phpstanCwe.ignoreUnmatched']);
});

it('does not suppress with an invalid reason or fingerprint but marks the ignore as used', function (): void {
    $short = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent(['reason' => 'one'])]);
    $bad = new CweIgnoreSet(78, __FILE__, [cweIgnoreEvent(['fingerprint' => 'abc'])]);

    expect($short->suppressesAt(str_repeat('a', 64), 12))->toBeFalse()
        ->and($bad->suppressesAt('abc', 12))->toBeFalse()
        ->and(array_map(static fn ($e) => $e->getIdentifier(), $short->reports()))->toBe(['phpstanCwe.ignoreReason'])
        ->and(array_map(static fn ($e) => $e->getIdentifier(), $bad->reports()))->toBe(['phpstanCwe.ignoreFingerprint']);
});

it('reports malformed, short and unmatched ignores', function (): void {
    $set = new CweIgnoreSet(78, __FILE__, [
        cweIgnoreEvent(['fingerprint' => '', 'reason' => '', 'line' => 2]),
        cweIgnoreEvent(['line' => 9]),
    ]);
    $reports = $set->reports();

    expect($reports)->toHaveCount(3)
        ->and($reports[0]->getMessage())->toBe('CWE-78 ignore must include a 64-character fingerprint.')
        ->and($reports[0]->getLine())->toBe(2)
        ->and($reports[0]->getFile())->toBe(__FILE__)
        ->and($reports[1]->getMessage())->toBe('CWE-78 ignore requires a reason with at least two words.')
        ->and($reports[1]->getIdentifier())->toBe('phpstanCwe.ignoreReason')
        ->and($reports[2]->getIdentifier())->toBe('phpstanCwe.ignoreUnmatched')
        ->and($reports[2]->getLine())->toBe(9)
        ->and($reports[2]->getMessage())->toBe('CWE-78 ignore fingerprint does not match a finding. Review or remove this ignore.');
});

it('strips comments from statements inside an expression text', function (): void {
    $statement = new Echo_([new Variable('a')], ['comments' => [new Comment('// inner')]]);
    $expression = new Closure(['stmts' => [$statement]]);

    expect(ExpressionText::of($expression))->not->toContain('inner');
});

it('counts the lines before an ignore that starts after a line break', function (): void {
    $node = new Echo_([new Variable('a')], ['comments' => [new Comment("// note\n// @phpstan-ignore\n phpstanCwe.cwe78.abc (two words)", 4)]]);
    $events = (new CweIgnoreCollector())->processNode($node, $this->createStub(Scope::class));

    expect($events[0]['line'])->toBe(5);
});

it('collects ignore lines and trimmed reasons from the comment text', function (): void {
    $node = new Echo_([new Variable('a')], [
        'startLine' => 5,
        'endLine' => 5,
        'startTokenPos' => 1,
        'endTokenPos' => 2,
        'comments' => [new Comment("\n@phpstan-ignore phpstanCwe.cwe78." . str_repeat('a', 64) . ' (  two words  )', 10)],
    ]);
    $scope = $this->createStub(Scope::class);
    $events = (new CweIgnoreCollector())->processNode($node, $scope);

    expect($events[0]['line'])->toBe(11)
        ->and($events[0]['reason'])->toBe('two words');
});

it('consumes the first invalid ignore for a finding and reports the second as unmatched', function (): void {
    $fingerprint = str_repeat('a', 64);
    $set = new CweIgnoreSet(78, __FILE__, [
        cweIgnoreEvent(['reason' => 'one', 'line' => 3]),
        cweIgnoreEvent(['reason' => 'two', 'line' => 8]),
    ]);

    expect($set->suppressesAt($fingerprint, 12))->toBeFalse()
        ->and(array_map(static fn ($e) => [$e->getIdentifier(), $e->getLine()], $set->reports()))
        ->toBe([['phpstanCwe.ignoreReason', 3], ['phpstanCwe.ignoreReason', 8], ['phpstanCwe.ignoreUnmatched', 8]]);
});
