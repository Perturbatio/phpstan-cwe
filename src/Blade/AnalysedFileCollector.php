<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Blade;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Node\FileNode;

/** @implements Collector<FileNode, true> */
final class AnalysedFileCollector implements Collector
{
    public function getNodeType(): string
    {
        return FileNode::class;
    }

    public function processNode(Node $node, Scope $scope): bool
    {
        return true;
    }
}
