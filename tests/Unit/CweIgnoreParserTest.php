<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweIgnoreParser;
use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Stmt\Trait_;
use PHPStan\Parser\Parser;

covers(CweIgnoreParser::class);

it('skips a statement without native annotations and filters the next trait', function (): void {
    $statement = new Nop();
    $trait = new Trait_('View', [], ['linesToIgnore' => [6 => ['phpstanCwe.cwe79.abc']]]);
    $parser = $this->createStub(Parser::class);
    $parser->method('parseString')->willReturn([$statement, $trait]);

    expect((new CweIgnoreParser($parser))->parseString('<?php ; trait View {}'))->toBe([$statement, $trait])
        ->and($statement->hasAttribute('linesToIgnore'))->toBeFalse()
        ->and($trait->getAttribute('linesToIgnore'))->toBe([]);
});

it('removes package annotation identifiers without changing native annotations', function (): void {
    $packageIgnore = ['name' => 'phpstanCwe.cwe79.abc', 'comment' => 'Reviewed output'];
    $nativeIgnore = ['name' => 'phpstanCwe.cwe79', 'comment' => 'Native ignore'];
    $first = new Nop(['linesToIgnore' => [
        1 => null,
        2 => [$packageIgnore, $nativeIgnore],
        3 => ['phpstanCwe.cwe95.abc'],
    ]]);
    $trait = new Trait_('View', [], ['linesToIgnore' => [6 => [$packageIgnore]]]);
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn([$first, $trait]);
    $parser->method('parseString')->willReturn([]);
    $filter = new CweIgnoreParser($parser);

    expect($filter->parseFile('view.php'))->toBe([$first, $trait])
        ->and($first->getAttribute('linesToIgnore'))->toBe([1 => null, 2 => [$nativeIgnore]])
        ->and($trait->getAttribute('linesToIgnore'))->toBe([])
        ->and($filter->parseString(''))->toBe([]);
});
