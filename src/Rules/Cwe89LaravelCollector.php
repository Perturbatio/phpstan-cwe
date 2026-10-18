<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArgPlaceholder;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\AssignOp\Concat as ConcatAssign;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\DNumber;
use PhpParser\Node\Scalar\EncapsedStringPart;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\VariadicPlaceholder;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;

/**
 * An assignment records a value stored in a variable. A sink records a SQL
 * call that can use that value.
 *
 * @phpstan-type LaravelSqlAssignment array{
 *     kind: 'assignment',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     variable: string,
 *     dynamic: bool,
 *     request: bool,
 *     unknown: bool,
 *     variables: list<string>
 * }
 * @phpstan-type LaravelSqlSink array{
 *     kind: 'sink',
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     line: int,
 *     dynamic: bool,
 *     request: bool,
 *     unknown: bool,
 *     variables: list<string>
 * }
 * @phpstan-type LaravelSqlEvent LaravelSqlAssignment|LaravelSqlSink
 * @implements Collector<Node, LaravelSqlEvent|null>
 */
final class Cwe89LaravelCollector implements Collector
{
    private const array BUILDER_CLASSES = [
        'Illuminate\Database\Eloquent\Builder',
        'Illuminate\Database\Eloquent\Relations\Relation',
        'Illuminate\Database\Query\Builder',
    ];
    private const array RAW_METHODS = [
        'fromraw',
        'groupbyraw',
        'havingraw',
        'orhavingraw',
        'orwhereraw',
        'orderbyraw',
        'selectraw',
        'whereraw',
    ];
    private const array REQUEST_VARIABLES = ['_GET', '_POST', '_COOKIE', '_REQUEST'];

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return LaravelSqlEvent|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (($node instanceof Assign || $node instanceof ConcatAssign)
            && $node->var instanceof Variable
            && is_string($node->var->name)
        ) {
            $facts = $this->expressionFacts($node->expr);
            if ($node instanceof ConcatAssign) {
                // The .= operation also reads the old value of the variable
                $facts = $this->mergeFacts(
                    $facts,
                    ['dynamic' => true, 'request' => false, 'unknown' => false, 'variables' => [$node->var->name]],
                );
            }

            return [
                'kind' => 'assignment',
                ...$this->eventBase($node->getEndTokenPos(), $scope),
                'variable' => $node->var->name,
                'dynamic' => $facts['dynamic'],
                'request' => $facts['request'],
                'unknown' => $facts['unknown'],
                'variables' => $facts['variables'],
            ];
        }

        $query = $this->getQueryExpression($node, $scope);
        if ($query === null) {
            return null;
        }

        // Store the SQL value facts so the rule can check its source
        $facts = $this->expressionFacts($query);

        return [
            'kind' => 'sink',
            ...$this->eventBase($node->getStartTokenPos(), $scope),
            'line' => $node->getStartLine(),
            'dynamic' => $facts['dynamic'],
            'request' => $facts['request'],
            'unknown' => $facts['unknown'],
            'variables' => $facts['variables'],
        ];
    }

    private function getQueryExpression(Node $node, Scope $scope): ?Expr
    {
        if ($node instanceof MethodCall && $node->name instanceof Identifier
            && in_array(strtolower($node->name->toString()), self::RAW_METHODS, true)
        ) {
            $receiver = $scope->getType($node->var);
            foreach (self::BUILDER_CLASSES as $builderClass) {
                if ((new ObjectType($builderClass))->isSuperTypeOf($receiver)->yes()) {
                    return $this->argument($node->args, ['sql', 'expression']);
                }
            }
        }

        if ($node instanceof StaticCall && $node->name instanceof Identifier
            && in_array(strtolower($node->name->toString()), ['select', 'insert', 'update', 'delete'], true)
            && $node->class instanceof Name
            && $this->isDatabaseFacade($node->class, $scope)
        ) {
            return $this->argument($node->args, ['query', 'sql']);
        }

        return null;
    }

    private function isDatabaseFacade(Name $class, Scope $scope): bool
    {
        if (strtolower($scope->resolveName($class)) === 'illuminate\\support\\facades\\db') {
            return true;
        }

        // Laravel can register DB as a global class alias without a use statement.
        return $class->isUnqualified() && strtolower($class->toString()) === 'db';
    }

    /**
     * @param array<Arg|ArgPlaceholder|VariadicPlaceholder> $arguments
     * @param list<string> $names
     */
    private function argument(array $arguments, array $names): ?Expr
    {
        foreach ($arguments as $argument) {
            if ($argument instanceof Arg && $argument->name !== null
                && in_array(strtolower($argument->name->toString()), $names, true)
            ) {
                return $argument->value;
            }
        }

        $firstArgument = $arguments[0] ?? null;
        if ($firstArgument instanceof Arg && $firstArgument->name === null) {
            return $firstArgument->value;
        }

        return null;
    }

    /**
     * @return array{dynamic: bool, request: bool, unknown: bool, variables: list<string>}
     */
    private function expressionFacts(Node $node): array
    {
        if ($node instanceof String_ || $node instanceof LNumber || $node instanceof DNumber
            || $node instanceof EncapsedStringPart
        ) {
            return $this->emptyFacts();
        }

        if ($node instanceof Variable) {
            if (!is_string($node->name)) {
                return ['dynamic' => true, 'request' => false, 'unknown' => true, 'variables' => []];
            }
            if (in_array($node->name, self::REQUEST_VARIABLES, true)) {
                return ['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []];
            }

            return ['dynamic' => true, 'request' => false, 'unknown' => false, 'variables' => [$node->name]];
        }

        if ($node instanceof Expr\FuncCall && $node->name instanceof Name
            && strtolower($node->name->toString()) === 'request'
        ) {
            $facts = $this->childrenFacts($node);
            $facts['dynamic'] = true;
            $facts['request'] = true;

            return $facts;
        }

        $facts = $this->childrenFacts($node);
        if ($node instanceof Expr\FuncCall || $node instanceof Expr\MethodCall
            || $node instanceof Expr\StaticCall || $node instanceof Expr\New_
            || $node instanceof Expr\PropertyFetch || $node instanceof Expr\NullsafePropertyFetch
        ) {
            $facts['dynamic'] = true;
            $facts['unknown'] = true;
        }

        return $facts;
    }

    /**
     * @return array{dynamic: bool, request: bool, unknown: bool, variables: list<string>}
     */
    private function childrenFacts(Node $node): array
    {
        $facts = $this->emptyFacts();
        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                $facts = $this->mergeFacts($facts, $this->expressionFacts($child));
                continue;
            }
            if (!is_array($child)) {
                continue;
            }
            foreach ($child as $item) {
                if ($item instanceof Node) {
                    $facts = $this->mergeFacts($facts, $this->expressionFacts($item));
                }
            }
        }

        return $facts;
    }

    /**
     * @param array{dynamic: bool, request: bool, unknown: bool, variables: list<string>} $left
     * @param array{dynamic: bool, request: bool, unknown: bool, variables: list<string>} $right
     * @return array{dynamic: bool, request: bool, unknown: bool, variables: list<string>}
     */
    private function mergeFacts(array $left, array $right): array
    {
        return [
            'dynamic' => $left['dynamic'] || $right['dynamic'],
            'request' => $left['request'] || $right['request'],
            'unknown' => $left['unknown'] || $right['unknown'],
            'variables' => array_values(array_unique(array_merge($left['variables'], $right['variables']))),
        ];
    }

    /** @return array{dynamic: false, request: false, unknown: false, variables: list<never>} */
    private function emptyFacts(): array
    {
        return ['dynamic' => false, 'request' => false, 'unknown' => false, 'variables' => []];
    }

    /** @return array{file: string, scope: string, offset: int} */
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
