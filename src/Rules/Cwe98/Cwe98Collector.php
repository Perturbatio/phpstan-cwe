<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe98;

use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use Perturbatio\PhpstanCwe\LaravelRequestInput;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\Match_;
use PhpParser\Node\Expr\Ternary;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

/**
 * @phpstan-type Cwe98Facts array{sources: list<string>, requestProbability: int|null, unknown: bool, variables: array<string, int>}
 * @phpstan-type Cwe98Assignment array{kind: 'assignment', file: string, scope: string, offset: int, startOffset: int, variable: string, sources: list<string>, requestProbability: int|null, unknown: bool, variables: array<string, int>}
 * @phpstan-type Cwe98Sink array{kind: 'sink', file: string, scope: string, offset: int, startOffset: int, line: int, expression: string, sources: list<string>, requestProbability: int|null, unknown: bool, variables: array<string, int>}
 * @phpstan-type Cwe98Scope array{kind: 'scope', file: string, scope: string, offset: int, endOffset: int}
 * @phpstan-type Cwe98Event Cwe98Assignment|Cwe98Sink|Cwe98Scope
 * @implements Collector<Node, Cwe98Event|null>
 */
final class Cwe98Collector implements Collector
{
    private readonly LaravelRequestInput $laravelRequestInput;

    public function __construct(
        private readonly ReflectionProvider $reflectionProvider,
    ) {
        $this->laravelRequestInput = new LaravelRequestInput($reflectionProvider);
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return Cwe98Event|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if ($node instanceof Closure || $node instanceof ArrowFunction) {
            return [
                'kind' => 'scope',
                'file' => $scope->getFile(),
                'scope' => $this->scopeName($scope),
                'offset' => $node->getStartTokenPos(),
                'endOffset' => $node->getEndTokenPos(),
            ];
        }

        if (($node instanceof Assign || $node instanceof Concat)
            && $node->var instanceof Variable
            && is_string($node->var->name)
        ) {
            $facts = $this->expressionFacts($node->expr, $scope);
            if ($node instanceof Concat) {
                $facts['variables'][$node->var->name] = Cwe98Rule::getUnchangedInputProbability();
            }

            return [
                'kind' => 'assignment',
                'file' => $scope->getFile(),
                'scope' => $this->scopeName($scope),
                'offset' => $node->getEndTokenPos(),
                'startOffset' => $node->getStartTokenPos(),
                'variable' => $node->var->name,
                ...$facts,
            ];
        }

        if (!$node instanceof Include_) {
            return null;
        }

        $facts = $this->expressionFacts($node->expr, $scope);

        return [
            'kind' => 'sink',
            'file' => $scope->getFile(),
            'scope' => $this->scopeName($scope),
            'offset' => $node->getEndTokenPos(),
            'startOffset' => $node->getStartTokenPos(),
            'line' => $node->getStartLine(),
            'expression' => ExpressionText::of($node->expr),
            ...$facts,
        ];
    }

    /**
     * Find request sources and local variables in a filename expression.
     *
     * @return Cwe98Facts
     */
    private function expressionFacts(Node $node, Scope $scope): array
    {
        $detectedVariables = [];
        $hasDirectInput = RequestInput::inInclude(
            $node,
            $scope,
            $this->reflectionProvider,
            static function (string $variable) use (&$detectedVariables): bool {
                $detectedVariables[] = $variable;

                return false;
            },
        );
        $facts = $this->factsForNode($node, $scope, $detectedVariables, Cwe98Rule::getUnchangedInputProbability());
        if ($hasDirectInput && $facts['sources'] === []) {
            $facts['sources'][] = 'request input';
            $facts['requestProbability'] = Cwe98Rule::getUnchangedInputProbability();
        }

        return $facts;
    }

    /**
     * @param list<string> $detectedVariables
     * @return Cwe98Facts
     */
    private function factsForNode(Node $node, Scope $scope, array $detectedVariables, int $modifier): array
    {
        if ($node instanceof Closure || $node instanceof ArrowFunction) {
            return $this->emptyFacts(unknown: true);
        }

        if ($node instanceof Match_) {
            $facts = $this->emptyFacts();
            foreach ($node->arms as $arm) {
                $facts = $this->mergeFacts(
                    $facts,
                    $this->factsForNode($arm->body, $scope, $detectedVariables, $modifier),
                );
            }

            return $facts;
        }

        if ($node instanceof Ternary) {
            $facts = $node->if === null
                ? $this->factsForNode($node->cond, $scope, $detectedVariables, $modifier)
                : $this->emptyFacts();

            if ($node->if !== null) {
                $facts = $this->mergeFacts(
                    $facts,
                    $this->factsForNode($node->if, $scope, $detectedVariables, $modifier),
                );
            }

            return $this->mergeFacts(
                $facts,
                $this->factsForNode($node->else, $scope, $detectedVariables, $modifier),
            );
        }

        $source = $node instanceof Expr ? $this->requestSource($node, $scope) : null;
        if ($source !== null) {
            return [
                'sources' => [$source],
                'requestProbability' => $modifier,
                'unknown' => false,
                'variables' => [],
            ];
        }

        if ($node instanceof Variable) {
            if (!is_string($node->name)) {
                return $this->emptyFacts(unknown: true);
            }
            if (!in_array($node->name, $detectedVariables, true)) {
                return $this->emptyFacts();
            }

            return [
                'sources' => [],
                'requestProbability' => null,
                'unknown' => false,
                'variables' => [$node->name => $modifier],
            ];
        }

        $childModifier = $modifier;
        if ($node instanceof Expr\Cast\Int_ || $node instanceof Expr\Cast\Double) {
            $childModifier = min($modifier, Cwe98Rule::getNumericInputProbability());
        } elseif ($node instanceof Expr\CallLike) {
            $childModifier = min($modifier, Cwe98Rule::getTransformedInputProbability());
        }

        $facts = $this->emptyFacts();
        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                $facts = $this->mergeFacts(
                    $facts,
                    $this->factsForNode($child, $scope, $detectedVariables, $childModifier),
                );
                continue;
            }
            if (!is_array($child)) {
                continue;
            }
            foreach ($child as $item) {
                if ($item instanceof Node) {
                    $facts = $this->mergeFacts(
                        $facts,
                        $this->factsForNode($item, $scope, $detectedVariables, $childModifier),
                    );
                }
            }
        }

        if (($node instanceof Expr\CallLike
                && !$this->isKnownPathFunction($node, $scope))
            || $node instanceof Expr\PropertyFetch
            || $node instanceof Expr\NullsafePropertyFetch
        ) {
            $facts['unknown'] = true;
        }

        return $facts;
    }

    private function requestSource(Expr $node, Scope $scope): ?string
    {
        $isLaravelInput = fn (Node $expression): bool => $this->laravelRequestInput->isInput($expression, $scope);
        if ($isLaravelInput($node)) {
            return 'laravel:' . ExpressionText::of($node);
        }
        if (($node instanceof Variable || $node instanceof Expr\ArrayDimFetch)
            && RequestInput::inInclude($node, $scope, $this->reflectionProvider)
        ) {
            return 'php:' . ExpressionText::of($node);
        }

        return null;
    }

    /**
     * basename() and dirname() do not make a fixed path dynamic.
     */
    private function isKnownPathFunction(Expr\CallLike $call, Scope $scope): bool
    {
        if (!$call instanceof Expr\FuncCall || !$call->name instanceof Node\Name) {
            return false;
        }

        $function = $this->reflectionProvider->resolveFunctionName($call->name, $scope);

        return $function !== null && in_array(strtolower($function), ['basename', 'dirname'], true);
    }

    /**
     * @return Cwe98Facts
     */
    private function emptyFacts(bool $unknown = false): array
    {
        return [
            'sources' => [],
            'requestProbability' => null,
            'unknown' => $unknown,
            'variables' => [],
        ];
    }

    /**
     * @param Cwe98Facts $left
     * @param Cwe98Facts $right
     * @return Cwe98Facts
     */
    private function mergeFacts(array $left, array $right): array
    {
        $variables = $left['variables'];
        foreach ($right['variables'] as $name => $probability) {
            $variables[$name] = isset($variables[$name])
                ? max($variables[$name], $probability)
                : $probability;
        }

        $leftProbability = $left['requestProbability'];
        $rightProbability = $right['requestProbability'];
        $requestProbability = $leftProbability === null
            ? $rightProbability
            : ($rightProbability === null ? $leftProbability : max($leftProbability, $rightProbability));

        return [
            'sources' => array_values(array_unique([...$left['sources'], ...$right['sources']])),
            'requestProbability' => $requestProbability,
            'unknown' => $left['unknown'] || $right['unknown'],
            'variables' => $variables,
        ];
    }

    private function scopeName(Scope $scope): string
    {
        return ($scope->getClassReflection()?->getName() ?? '') . '::' . ($scope->getFunctionName() ?? 'file');
    }
}
