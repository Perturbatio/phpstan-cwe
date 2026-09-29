<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules;

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;
use Perturbatio\PhpstanCwe\CweReport;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;

/** @implements Rule<CollectedDataNode> */
final class Cwe79BladeRule implements Rule
{
    private const SEVERITY = 'high';
    private const PROBABILITY = 80;

    /** @param list<string> $directories */
    public function __construct(
        private readonly BladeTemplateScanner $scanner,
        private readonly array $directories,
        private readonly int $minProbability = 0,
    ) {
        CweReport::isEnabled($minProbability, self::PROBABILITY);
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if ($node->get(AnalysedFileCollector::class) === []
            || !CweReport::isEnabled($this->minProbability, self::PROBABILITY)
        ) {
            return [];
        }

        // Report the template location, not the PHP file that starts the scan.
        $errors = [];
        foreach ($this->scanner->scan($this->directories) as $finding) {
            $errors[] = CweReport::make(
                79,
                'A Blade raw echo prints a value without HTML escape.',
                self::SEVERITY,
                self::PROBABILITY,
                $finding['file'],
                $finding['line'],
            );
        }

        return $errors;
    }
}
