<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use Perturbatio\PhpstanCwe\LaravelRequestInput;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat as ConcatAssign;
use PhpParser\Node\Expr\Eval_;
use PhpParser\Node\Expr\Variable;
use PhpParser\PrettyPrinter\Standard;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\ShouldNotHappenException;

/**
 * @phpstan-type Cwe95Assignment array{
 *     kind: 'assignment',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     startOffset: int,
 *     variable: string,
 *     unknownMethodCall?: string,
 *     sources: list<string>,
 *     unknown: bool,
 *     variables: list<string>
 * }
 * @phpstan-type Cwe95Sink array{
 *     kind: 'sink',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     line: int,
 *     expression: string,
 *     sources: list<string>,
 *     unknown: bool,
 *     variables: list<string>
 * }
 * @phpstan-type Cwe95Scope array{
 *     kind: 'scope',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     endOffset: int
 * }
 * @phpstan-type Cwe95FlowEvent Cwe95Assignment|Cwe95Sink
 * @phpstan-type Cwe95Event Cwe95FlowEvent|Cwe95Scope
 * @implements Collector<Node, Cwe95Event|null>
 */
final class Cwe95Collector implements Collector
{
    /** @var list<string> */
    // The declaration cannot be covered; the collector test checks every default request root.
    // @pest-mutate-ignore
    private const array REQUEST_VARIABLES = ['_GET', '_POST', '_COOKIE', '_REQUEST'];

    private readonly Standard $prettyPrinter;
    private readonly ?LaravelRequestInput $laravelRequestInput;

    public function __construct(
        ReflectionProvider $reflectionProvider,
        bool $checkLaravelInput = false,
    ) {
        $this->prettyPrinter = new Standard();
        $this->laravelRequestInput = $checkLaravelInput
            ? new LaravelRequestInput($reflectionProvider)
            : null;
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /**
     * @param  Node  $node
     * @param  Scope  $scope
     * @return Cwe95Event|null
     * @throws ShouldNotHappenException
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            return [
                'kind' => 'scope',
                ...$this->eventBase($node->getStartTokenPos(), $scope),
                'endOffset' => $node->getEndTokenPos(),
            ];
        }

        if (($node instanceof Assign || $node instanceof ConcatAssign)
            && $node->var instanceof Variable
            && is_string($node->var->name)
        ) {
            $facts = $this->expressionFacts($node->expr, $scope);
            if ($node instanceof ConcatAssign && !in_array($node->var->name, $facts['variables'], true)) {
                $facts['variables'][] = $node->var->name;
            }
            if ($facts['unknown'] && ($node->expr instanceof Expr\MethodCall || $node->expr instanceof Expr\NullsafeMethodCall)) {
                $facts['unknownMethodCall'] = ExpressionText::of($node->expr);
            }

            return [
                'kind' => 'assignment',
                ...$this->eventBase($node->getEndTokenPos(), $scope),
                'startOffset' => $node->getStartTokenPos(),
                'variable' => $node->var->name,
                ...$facts,
            ];
        }

        if (!$node instanceof Eval_) {
            return null;
        }

        return [
            'kind' => 'sink',
            ...$this->eventBase($node->getStartTokenPos(), $scope),
            'line' => $node->getStartLine(),
            'expression' => $this->prettyPrinter->prettyPrintExpr($node),
            ...$this->expressionFacts($node->expr, $scope),
        ];
    }

    /**
     * Find request sources and local variables in an expression.
     * An unknown value is not proof that the value is safe.
     *
     * @return array{sources: list<string>, unknown: bool, variables: list<string>}
     */
    private function expressionFacts(Node $node, Scope $scope): array
    {
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            return ['sources' => [], 'unknown' => true, 'variables' => []];
        }

        if ($node instanceof Expr\ArrayDimFetch && $this->hasRequestVariableRoot($node)) {
            return [
                'sources' => ['php:' . $this->prettyPrinter->prettyPrintExpr($node)],
                'unknown' => false,
                'variables' => [],
            ];
        }

        if ($node instanceof Variable && is_string($node->name)
            && in_array($node->name, self::REQUEST_VARIABLES, true)
        ) {
            return ['sources' => ['php:$' . $node->name], 'unknown' => false, 'variables' => []];
        }

        if ($this->laravelRequestInput?->isInput($node, $scope)) {
            return [
                'sources' => ['laravel:' . $this->prettyPrinter->prettyPrintExpr($node)],
                'unknown' => false,
                'variables' => [],
            ];
        }

        if ($node instanceof Variable) {
            return is_string($node->name)
                ? ['sources' => [], 'unknown' => false, 'variables' => [$node->name]]
                : ['sources' => [], 'unknown' => true, 'variables' => []];
        }

        $facts = ['sources' => [], 'unknown' => false, 'variables' => []];
        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                $facts = $this->mergeFacts($facts, $this->expressionFacts($child, $scope));
                continue;
            }
            if (!is_array($child)) {
                continue;
            }
            foreach ($child as $item) {
                if ($item instanceof Node) {
                    $facts = $this->mergeFacts($facts, $this->expressionFacts($item, $scope));
                }
            }
        }

        if ($node instanceof Expr\CallLike || $node instanceof Expr\PropertyFetch
            || $node instanceof Expr\NullsafePropertyFetch
        ) {
            $facts['unknown'] = true;
        } elseif ($node instanceof Expr && $node->getSubNodeNames() === []) {
            $facts['unknown'] = true;
        }

        return $facts;
    }

    private function hasRequestVariableRoot(Expr $expression): bool
    {
        if ($expression instanceof Variable && is_string($expression->name)) {
            return in_array($expression->name, self::REQUEST_VARIABLES, true);
        }

        return $expression instanceof Expr\ArrayDimFetch && $this->hasRequestVariableRoot($expression->var);
    }

    /**
     * @param array{sources: list<string>, unknown: bool, variables: list<string>} $left
     * @param array{sources: list<string>, unknown: bool, variables: list<string>} $right
     * @return array{sources: list<string>, unknown: bool, variables: list<string>}
     */
    private function mergeFacts(array $left, array $right): array
    {
        return [
            'sources' => array_values(array_unique(array_merge($left['sources'], $right['sources']))),
            'unknown' => $left['unknown'] || $right['unknown'],
            'variables' => array_values(array_unique(array_merge($left['variables'], $right['variables']))),
        ];
    }

    /**
     * @param  int  $offset
     * @param  Scope  $scope
     * @return array{file: string, scope: string, offset: int}
     * @throws ShouldNotHappenException
     */
    private function eventBase(int $offset, Scope $scope): array
    {
        $function = $scope->getFunction();
        $callable = $function?->getName() ?? 'file';
        $class = $scope->getClassReflection()?->getName() ?? '';

        return [
            'file' => $scope->getFile(),
            'scope' => $class . '::' . $callable,
            'offset' => $offset,
        ];
    }
}
