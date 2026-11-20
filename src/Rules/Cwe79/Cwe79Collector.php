<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

/**
 * @phpstan-type HtmlAssignment array{kind: 'assignment', scope: string, offset: int, startOffset: int, variable: string, request: bool, variables: list<string>, calledVariables?: list<string>, isArrow?: bool, copiedVariable?: string}
 * @phpstan-type HtmlSink array{kind: 'sink', scope: string, offset: int, startOffset: int, line: int, expression: string, request: bool, variables: list<string>, calledVariables?: list<string>}
 * @phpstan-type HtmlScope array{kind: 'scope', scope: string, offset: int, endOffset: int}
 * @phpstan-type HtmlFlowEvent HtmlAssignment|HtmlSink
 * @phpstan-type HtmlEvent HtmlFlowEvent|HtmlScope
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
        $scopeName = $scope->getClassReflection()?->getName() . '::' . ($scope->getFunctionName() ?? 'file');
        if ($node instanceof Closure || $node instanceof ArrowFunction) {
            return [
                'kind' => 'scope',
                'scope' => $scopeName,
                'offset' => $node->getStartTokenPos(),
                'endOffset' => $node->getEndTokenPos(),
            ];
        }

        $variables = [];
        $calledVariables = [];
        // Record dependencies without deciding their source yet. For `$html = $name`,
        // the flow resolver reads the earlier facts for `name`. Return false here
        // so the expression scan can find other variables and direct request input.
        $isAssignedInput = static function (string $variable) use (&$variables): bool {
            $variables[] = $variable;

            return false;
        };
        $isCalledInput = static function (string $variable) use (&$calledVariables): bool {
            $calledVariables[] = $variable;

            return false;
        };
        $containsInput = fn (Node $expression, ?callable $assignedInput = null, ?callable $calledInput = null): bool => RequestInput::inHtml(
            $expression,
            $scope,
            $this->reflectionProvider,
            $assignedInput ?? $isAssignedInput,
            $calledInput ?? $isCalledInput,
        );

        if (($node instanceof Assign || $node instanceof Concat)
            && $node->var instanceof Variable && is_string($node->var->name)
        ) {
            $isArrow = $node instanceof Assign && $node->expr instanceof ArrowFunction;
            if ($isArrow) {
                $parameters = [];
                foreach ($node->expr->params as $parameter) {
                    if ($parameter->var instanceof Node\Expr\Error) {
                        continue;
                    }
                    if (is_string($parameter->var->name)) {
                        $parameters[] = $parameter->var->name;
                    }
                }
                $request = $containsInput(
                    $node->expr->expr,
                    static fn (string $variable): bool => !in_array($variable, $parameters, true) && $isAssignedInput($variable),
                    static fn (string $variable): bool => !in_array($variable, $parameters, true) && $isCalledInput($variable),
                );
            } else {
                $request = $containsInput($node->expr);
            }
            if ($node instanceof Concat) {
                // `$html .= $name` uses both the old `html` and the new `name`.
                $variables[] = $node->var->name;
            }

            return [
                'kind' => 'assignment',
                'scope' => $scopeName,
                'offset' => $node->getEndTokenPos(),
                'startOffset' => $node->getStartTokenPos(),
                'variable' => $node->var->name,
                'request' => $request,
                'variables' => array_values(array_unique($variables)),
                ...($calledVariables === [] ? [] : ['calledVariables' => array_values(array_unique($calledVariables))]),
                ...($isArrow ? ['isArrow' => true] : []),
                ...($node instanceof Assign && $node->expr instanceof Variable && is_string($node->expr->name) ? ['copiedVariable' => $node->expr->name] : []),
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
            'startOffset' => $node->getStartTokenPos(),
            'line' => $node->getStartLine(),
            'expression' => implode(', ', array_map(ExpressionText::of(...), $expressions)),
            'request' => $request,
            'variables' => array_values(array_unique($variables)),
            ...($calledVariables === [] ? [] : ['calledVariables' => array_values(array_unique($calledVariables))]),
        ];
    }
}
