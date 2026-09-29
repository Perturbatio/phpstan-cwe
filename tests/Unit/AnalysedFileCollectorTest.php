<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;

it('collects analysed PHP files', function (): void {
    $collector = new AnalysedFileCollector();

    expect($collector->getNodeType())->toBe(FileNode::class)
        ->and($collector->processNode(new FileNode([]), $this->createMock(Scope::class)))->toBeTrue();
});
