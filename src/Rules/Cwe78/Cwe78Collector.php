<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe78;

use Perturbatio\PhpstanCwe\LaravelRequestInput;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat as ConcatAssign;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ShellExec;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

/**
 * @phpstan-type Cwe78Assignment array{
 *     kind: 'assignment',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     variable: string,
 *     request: bool,
 *     hasStaticText: bool,
 *     variables: list<string>
 * }
 * @phpstan-type Cwe78Sink array{
 *     kind: 'sink',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     line: int,
 *     request: bool,
 *     hasStaticText: bool,
 *     throughAssignment: bool,
 *     variables: list<string>
 * }
 * @phpstan-type Cwe78Event Cwe78Assignment|Cwe78Sink
 * @implements Collector<Node, Cwe78Event|null>
 */
final class Cwe78Collector implements Collector
{
    // These functions run commands and can expose a system to unsafe input
    // @pest-mutate-ignore
    private const array SINKS = ['exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open'];
    // These PHP arrays can hold input from an HTTP request
    // @pest-mutate-ignore
    private const array REQUEST_VARIABLES = ['_GET', '_POST', '_COOKIE', '_REQUEST'];

    public function __construct(
        private readonly ReflectionProvider $reflectionProvider,
        private readonly ?LaravelRequestInput $laravelRequestInput = null,
    ) {
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return list<string> */
    public static function getSupportedFunctions(): array
    {
        return self::SINKS;
    }

    /** @return list<string> */
    public static function getRequestVariables(): array
    {
        return self::REQUEST_VARIABLES;
    }

    /** @return Cwe78Event|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // Record assignments so the rule can follow simple local variables
        if ($node instanceof Assign || $node instanceof ConcatAssign) {
            if (!$node->var instanceof Expr\Variable) {
                return null;
            }
            $variableName = $this->variableName($node->var);
            if ($variableName === null) {
                return null;
            }

            $facts = $this->expressionFacts($node->expr, $scope);
            if ($node instanceof ConcatAssign) {
                // Concatenation also keeps the old value and adds fixed text
                $facts['request'] = $facts['request'] || in_array($variableName, self::getRequestVariables(), true);
                $facts['hasStaticText'] = true;
                if (!in_array($variableName, $facts['variables'], true)) {
                    $facts['variables'][] = $variableName;
                }
            }

            return [
                'kind' => 'assignment',
                ...$this->eventBase($node->getEndTokenPos(), $scope),
                'variable' => $variableName,
                'request' => $facts['request'],
                'hasStaticText' => $facts['hasStaticText'],
                'variables' => $facts['variables'],
            ];
        }

        if ($node instanceof ShellExec) {
            $facts = $this->expressionFacts($node, $scope);
        } else {
            // Read only calls that match a supported command function
            $command = $this->getCommand($node, $scope);
            if ($command === null) {
                return null;
            }
            $facts = $this->expressionFacts($command, $scope);
        }

        return [
            'kind' => 'sink',
            ...$this->eventBase($node->getStartTokenPos(), $scope),
            'line' => $node->getStartLine(),
            'request' => $facts['request'],
            'hasStaticText' => $facts['hasStaticText'],
            'throughAssignment' => $facts['variables'] !== [],
            'variables' => $facts['variables'],
        ];
    }

    private function variableName(Expr\Variable $variable): ?string
    {
        return is_string($variable->name) ? $variable->name : null;
    }

    private function getCommand(Node $node, Scope $scope): ?Expr
    {
        // Resolve aliases before comparing the function with the supported list
        if (!$node instanceof FuncCall || !$node->name instanceof Node\Name) {
            return null;
        }
        $function = $this->reflectionProvider->resolveFunctionName($node->name, $scope);
        if ($function === null || !in_array(strtolower($function), self::getSupportedFunctions(), true)) {
            return null;
        }

        foreach ($node->args as $argument) {
            if (!$argument instanceof Arg) {
                continue;
            }
            if ($argument->name !== null && strtolower($argument->name->toString()) === 'command') {
                return $this->commandValue($function, $argument->value);
            }
            if ($argument->name === null) {
                return $this->commandValue($function, $argument->value);
            }
        }

        return null;
    }

    private function commandValue(string $function, Expr $value): Expr
    {
        // proc_open accepts an argument array. Its first item is the executable
        if (strtolower($function) !== 'proc_open') {
            return $value;
        }

        if (!$value instanceof Array_) {
            return $value;
        }

        return $this->firstArrayItem($value) ?? $value;
    }

    private function firstArrayItem(Array_ $array): ?Expr
    {
        return ($array->items[0] ?? null)?->value;
    }

    /**
     * Find request input, fixed text, and local variables in an expression
     * This check does not prove that other values are safe
     *
     * @return array{request: bool, hasStaticText: bool, variables: list<string>}
     */
    private function expressionFacts(Node $node, Scope $scope): array
    {
        $function = $node instanceof Expr\FuncCall && $node->name instanceof Node\Name
            ? $this->reflectionProvider->resolveFunctionName($node->name, $scope)
            : null;
        if ($function !== null && strtolower($function) === 'escapeshellarg') {
            return ['request' => false, 'hasStaticText' => false, 'variables' => []];
        }

        if ($this->laravelRequestInput?->isInput($node, $scope)) {
            return ['request' => true, 'hasStaticText' => false, 'variables' => []];
        }

        $facts = [
            'request' => false,
            'hasStaticText' => $node instanceof String_ || $node instanceof InterpolatedStringPart,
            'variables' => [],
        ];
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            if (in_array($node->name, self::getRequestVariables(), true)) {
                $facts['request'] = true;
            } else {
                $facts['variables'][] = $node->name;
            }
        }

        if ($node instanceof Expr\ArrayDimFetch) {
            // Check both the array and its key for request input
            $arrayFacts = $this->expressionFacts($node->var, $scope);
            $dimFacts = $node->dim === null
                ? ['request' => false, 'variables' => []]
                : $this->expressionFacts($node->dim, $scope);

            return [
                'request' => $arrayFacts['request'] || $dimFacts['request'],
                'hasStaticText' => $arrayFacts['hasStaticText'],
                'variables' => array_values(array_unique(array_merge($arrayFacts['variables'], $dimFacts['variables']))),
            ];
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                $facts = $this->mergeFacts($facts, $this->expressionFacts($child, $scope));
            } elseif (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node) {
                        $facts = $this->mergeFacts($facts, $this->expressionFacts($item, $scope));
                    }
                }
            }
        }

        return $facts;
    }

    /**
     * @param array{request: bool, hasStaticText: bool, variables: list<string>} $left
     * @param array{request: bool, hasStaticText: bool, variables: list<string>} $right
     * @return array{request: bool, hasStaticText: bool, variables: list<string>}
     */
    private function mergeFacts(array $left, array $right): array
    {
        // Keep one copy of each local variable name
        return [
            'request' => $left['request'] || $right['request'],
            'hasStaticText' => $left['hasStaticText'] || $right['hasStaticText'],
            'variables' => array_values(array_unique(array_merge($left['variables'], $right['variables']))),
        ];
    }

    /** @return array{file: string, scope: string, offset: int} */
    private function eventBase(int $offset, Scope $scope): array
    {
        // Use the function name to keep variable facts separate by scope
        return [
            'file' => $scope->getFile(),
            'scope' => $scope->getFunctionName() ?? 'file',
            'offset' => $offset,
        ];
    }
}
