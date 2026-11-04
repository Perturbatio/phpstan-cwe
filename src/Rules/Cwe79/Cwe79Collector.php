<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

/**
 * @phpstan-type HtmlAssignment array{kind: 'assignment', scope: string, offset: int, variable: string, request: bool, variables: list<string>}
 * @phpstan-type HtmlSink array{kind: 'sink', scope: string, offset: int, line: int, request: bool, variables: list<string>}
 * @phpstan-type HtmlEvent HtmlAssignment|HtmlSink
 * @implements Collector<Node, HtmlEvent|null>
 */
final class Cwe79Collector implements Collector
{
    public function __construct(private readonly ReflectionProvider $reflectionProvider)
    {
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return HtmlEvent|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        $variables = [];
        // Record dependencies without deciding their source yet. For `$html = $name`,
        // the flow resolver reads the earlier facts for `name`. Return false here
        // so the expression scan can find other variables and direct request input.
        $isAssignedInput = static function (string $variable) use (&$variables): bool {
            $variables[] = $variable;

            return false;
        };
        $containsInput = fn (Node $expression): bool => RequestInput::inHtml(
            $expression,
            $scope,
            $this->reflectionProvider,
            $isAssignedInput,
        );

        $scopeName = $scope->getClassReflection()?->getName() . '::' . ($scope->getFunctionName() ?? 'file');

        if (($node instanceof Assign || $node instanceof Concat)
            && $node->var instanceof Variable && is_string($node->var->name)
        ) {
            if ($scope->isInAnonymousFunction()) {
                return null;
            }
            $request = $containsInput($node->expr);
            if ($node instanceof Concat) {
                // `$html .= $name` uses both the old `html` and the new `name`.
                $variables[] = $node->var->name;
            }

            return [
                'kind' => 'assignment',
                'scope' => $scopeName,
                'offset' => $node->getEndTokenPos(),
                'variable' => $node->var->name,
                'request' => $request,
                'variables' => array_values(array_unique($variables)),
            ];
        }

        $expressions = $node instanceof Echo_ ? $node->exprs : ($node instanceof Print_ ? [$node->expr] : []);
        if ($expressions === []) {
            return null;
        }
        $request = false;
        foreach ($expressions as $expression) {
            $request = $containsInput($expression) || $request;
        }

        return [
            'kind' => 'sink',
            'scope' => $scopeName,
            'offset' => $node->getEndTokenPos(),
            'line' => $node->getStartLine(),
            'request' => $request,
            // Do not mix closure variables with variables in the outer scope.
            'variables' => $scope->isInAnonymousFunction() ? [] : array_values(array_unique($variables)),
        ];
    }
}
