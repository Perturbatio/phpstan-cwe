<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe89;

use Perturbatio\PhpstanCwe\LaravelRequestInput;
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
use PhpParser\Node\VariadicPlaceholder;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\ShouldNotHappenException;
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
    private readonly LaravelRequestInput $laravelRequestInput;

    public function __construct(ReflectionProvider $reflectionProvider)
    {
        $this->laravelRequestInput = new LaravelRequestInput($reflectionProvider);
    }

    // These classes provide methods that accept raw SQL text.
    /** @return list<string> */
    public static function getBuilderClasses(): array
    {
        return [
            'Illuminate\Database\Eloquent\Builder',
            'Illuminate\Database\Eloquent\Relations\Relation',
            'Illuminate\Database\Query\Builder',
        ];
    }

    /** @return list<string> */
    public static function getRawMethods(): array
    {
        return [
            'fromraw',
            'groupbyraw',
            'havingraw',
            'orhavingraw',
            'orwhereraw',
            'orderbyraw',
            'selectraw',
            'whereraw',
        ];
    }

    /** @return list<string> */
    public static function getRequestVariables(): array
    {
        return ['_GET', '_POST', '_COOKIE', '_REQUEST'];
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return LaravelSqlEvent|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // Save assignments so the rule can follow simple local variables
        if (($node instanceof Assign || $node instanceof ConcatAssign)
            && $node->var instanceof Variable
            && is_string($node->var->name)
        ) {
            $facts = $this->expressionFacts($node->expr, $scope);
            if ($node instanceof ConcatAssign) {
                // Concatenation also keeps the old value of the variable
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

        // Store facts about SQL text so the rule can check its source
        $facts = $this->expressionFacts($query, $scope);

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
        // Check raw query methods only on known Laravel query builders
        if ($node instanceof MethodCall && $node->name instanceof Identifier
            && in_array(strtolower($node->name->toString()), self::getRawMethods(), true)
        ) {
            $receiver = $scope->getType($node->var);
            foreach (self::getBuilderClasses() as $builderClass) {
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
            // The DB facade accepts SQL text in its first argument.
            return $this->argument($node->args, ['query', 'sql']);
        }

        return null;
    }

    private function isDatabaseFacade(Name $class, Scope $scope): bool
    {
        if (strtolower($scope->resolveName($class)) === 'illuminate\\support\\facades\\db') {
            return true;
        }

        // Laravel can register DB as a global class alias without a use statement
        return $class->isUnqualified() && strtolower($class->toString()) === 'db';
    }

    /**
     * @param array<Arg|ArgPlaceholder|VariadicPlaceholder> $arguments
     * @param list<string> $names
     */
    private function argument(array $arguments, array $names): ?Expr
    {
        // Use a matching named argument when present
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
     * @throws ShouldNotHappenException
     */
    private function expressionFacts(Node $node, Scope $scope): array
    {
        // A local variable needs facts from its earlier assignment
        if ($node instanceof Variable) {
            if (!is_string($node->name)) {
                return ['dynamic' => true, 'request' => false, 'unknown' => true, 'variables' => []];
            }
            if (in_array($node->name, self::getRequestVariables(), true)) {
                return ['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []];
            }

            return ['dynamic' => true, 'request' => false, 'unknown' => false, 'variables' => [$node->name]];
        }

        // Only Laravel's grammar can wrap an SQL identifier safely
        // A method with the same name on another class does not count
        if ($node instanceof MethodCall && $node->name instanceof Identifier
            && strtolower($node->name->toString()) === 'wrap'
            && (new ObjectType('Illuminate\Database\Grammar'))->isSuperTypeOf($scope->getType($node->var))->yes()
        ) {
            $column = $this->argument($node->args, ['value']);
            // Check strings only. Laravel does not quote raw expression objects
            if ($column !== null && $scope->getType($column)->isString()->yes()) {
                // Identifier wrapping does not protect SQL string values
                return $this->emptyFacts();
            }
        }

        if ($this->laravelRequestInput->isInput($node, $scope)) {
            return ['dynamic' => true, 'request' => true, 'unknown' => false, 'variables' => []];
        }

        $facts = $this->childrenFacts($node, $scope);
        if ($node instanceof Expr\CallLike
            || $node instanceof Expr\PropertyFetch || $node instanceof Expr\NullsafePropertyFetch
        ) {
            // Mark values from calls as unknown unless a rule above can classify them
            $facts['dynamic'] = true;
            $facts['unknown'] = true;
        }

        return $facts;
    }

    /**
     * @return array{dynamic: bool, request: bool, unknown: bool, variables: list<string>}
     */
    private function childrenFacts(Node $node, Scope $scope): array
    {
        // Keep the scope so PHPStan can check grammar and argument types
        $facts = $this->emptyFacts();
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

        return $facts;
    }

    /**
     * @param array{dynamic: bool, request: bool, unknown: bool, variables: list<string>} $left
     * @param array{dynamic: bool, request: bool, unknown: bool, variables: list<string>} $right
     * @return array{dynamic: bool, request: bool, unknown: bool, variables: list<string>}
     */
    private function mergeFacts(array $left, array $right): array
    {
        // Combine source facts and keep each variable name once
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
        // Use class and function names to keep facts separate by scope
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
