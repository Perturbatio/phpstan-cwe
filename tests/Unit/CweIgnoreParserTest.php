<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Ignore\CweIgnoreParser;
use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Stmt\Trait_;
use PHPStan\Parser\Parser;

covers(CweIgnoreParser::class);

it('removes package ignore identifiers without changing native ignores', function (): void {
    $packageIgnore = ['name' => 'phpstanCwe.cwe79.abc', 'comment' => 'Reviewed output'];
    $nativeIgnore = ['name' => 'phpstanCwe.cwe79', 'comment' => 'Native ignore'];
    $first = new Nop(['linesToIgnore' => [
        2 => [$packageIgnore, $nativeIgnore],
        3 => ['phpstanCwe.cwe95.abc'],
        4 => null,
    ]]);
    $trait = new Trait_('View', [], ['linesToIgnore' => [6 => [$packageIgnore]]]);
    $parser = $this->createStub(Parser::class);
    $parser->method('parseFile')->willReturn([$first, $trait]);
    $parser->method('parseString')->willReturn([]);
    $filter = new CweIgnoreParser($parser);

    expect($filter->parseFile('view.php'))->toBe([$first, $trait])
        ->and($first->getAttribute('linesToIgnore'))->toBe([2 => [$nativeIgnore], 4 => null])
        ->and($trait->getAttribute('linesToIgnore'))->toBe([])
        ->and($filter->parseString(''))->toBe([]);
});
