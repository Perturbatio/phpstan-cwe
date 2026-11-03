<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

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

    public function __construct(
        private readonly ReflectionProvider $reflectionProvider,
        private readonly int $minProbability = 0,
    ) {
        // Check the minimum score when PHPStan creates this rule.
        CweReport::isEnabled($minProbability, self::getProbability());
    }

    public static function getProbability(): int
    {
        return 80;
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        // Do not scan output when this rule is below the configured score
        if (!CweReport::isEnabled($this->minProbability, self::getProbability())) {
            return [];
        }

        if ($node instanceof Print_) {
            $expressions = [$node->expr];
        } elseif ($node instanceof Echo_) {
            $expressions = $node->exprs;
        } else {
            return [];
        }

        // Check direct output only. This rule does not follow assigned values
        foreach ($expressions as $expression) {
            // Report when request input reaches HTML without an escape call
            if (RequestInput::inHtml($expression, $scope, $this->reflectionProvider)) {
                return [CweReport::make(79, 'Request input is sent to HTML without an HTML escape call.', self::SEVERITY, self::getProbability())];
            }
        }

        return [];
    }
}
