<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe306;

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\IgnoreReason;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Parser\Parser;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<CollectedDataNode> */
final class Cwe306LaravelRule implements Rule
{
    public function __construct(
        private readonly Parser $parser,
        private readonly LaravelAuthenticationScanner $scanner,
        private readonly int $minProbability = 0,
    ) {
        CweReport::isEnabled($minProbability, $minProbability);
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (!$this->scanner->hasCriticalOperations()) {
            return [
                RuleErrorBuilder::message('CWE-306 is enabled, but no critical operations are configured. Set phpstanCwe.cwe306CriticalOperations to the functions or methods that require authentication.')
                    ->identifier('phpstanCwe.cwe306Configuration')
                    ->build(),
            ];
        }
        $files = [];
        $reports = [];
        // Collect all analysed files before scanning. A route and its controller
        // can be in different files. Do not load or execute application code.
        foreach (array_keys($node->get(AnalysedFileCollector::class)) as $file) {
            $files[$file] = $this->parser->parseFile($file);
            // Check ignore reasons before filtering scores. A filtered finding
            // must not allow an invalid reason to pass without an error.
            array_push($reports, ...IgnoreReason::reports($files[$file], $file, 'phpstanCwe.cwe306', 306));
        }
        foreach ($this->scanner->scan($files, $node->get(ChainedCallCollector::class)) as $finding) {
            if (!CweReport::isEnabled($this->minProbability, $finding['probability'])) {
                continue;
            }
            // Report at the route so two routes to one action remain separate.
            $reports[] = CweReport::make(
                306,
                sprintf('A Laravel route reaches critical operation %s without a supported authentication control.', $finding['operation']),
                'high',
                $finding['probability'],
                $finding['file'],
                $finding['line'],
                'Require authentication before this operation. Unknown middleware and calls can contain controls that this rule cannot resolve.',
            );
        }

        return $reports;
    }
}
