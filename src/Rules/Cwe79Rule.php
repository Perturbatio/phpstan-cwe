<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules;

use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Rules\Rule;

/** @implements Rule<Node> */
final class Cwe79Rule implements Rule
{
    private const string SEVERITY = 'high';
    private const int PROBABILITY = 80;

    public function __construct(
        private readonly ReflectionProvider $reflectionProvider,
        private readonly int $minProbability = 0,
    ) {
        CweReport::isEnabled($minProbability, self::PROBABILITY);
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        if (!CweReport::isEnabled($this->minProbability, self::PROBABILITY)) {
            return [];
        }

        if ($node instanceof Print_) {
            $expressions = [$node->expr];
        } elseif ($node instanceof Echo_) {
            $expressions = $node->exprs;
        } else {
            return [];
        }

        // Check output text here. This rule does not follow assigned values.
        foreach ($expressions as $expression) {
            if (RequestInput::inHtml($expression, $scope, $this->reflectionProvider)) {
                return [CweReport::make(79, 'Request input is sent to HTML without an HTML escape call.', self::SEVERITY, self::PROBABILITY)];
            }
        }

        return [];
    }
}
