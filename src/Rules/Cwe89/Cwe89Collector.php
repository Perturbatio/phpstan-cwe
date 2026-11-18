<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe89;

use Perturbatio\PhpstanCwe\Ignore\ExpressionText;
use Perturbatio\PhpstanCwe\RequestInput;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArgPlaceholder;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\VariadicPlaceholder;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;

/**
 * Collect SQL calls to PDO, mysqli, and mysqli functions that use request input in query text.
 *
 * @phpstan-type DirectSqlSink array{
 *     file: string,
 *     scope: string,
 *     offset: int,
 *     line: int,
 *     expression: string
 * }
 * @implements Collector<Node, DirectSqlSink|null>
 */
final class Cwe89Collector implements Collector
{
    public function __construct(private readonly ReflectionProvider $reflectionProvider)
    {
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /** @return DirectSqlSink|null */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // Check query text before the call. Bound values are not query text
        $query = $this->getQuery($node, $scope);
        if ($query === null || !RequestInput::inSql($query, $scope, $this->reflectionProvider)) {
            return null;
        }

        // getQuery() returns a query only for a supported function or method call
        /** @var FuncCall|MethodCall $node */
        /** @var Name|Identifier $name */
        $name = $node->name;

        return [
            'file' => $scope->getFile(),
            'scope' => ($scope->getClassReflection()?->getName() ?? '') . '::' . ($scope->getFunction()?->getName() ?? 'file'),
            'offset' => $node->getStartTokenPos(),
            'line' => $node->getStartLine(),
            'expression' => strtolower($name->toString()) . ': ' . ExpressionText::of($query),
        ];
    }

    private function getQuery(Node $node, Scope $scope): ?Expr
    {
        // Check only supported database functions and database objects
        if ($node instanceof FuncCall && $node->name instanceof Name) {
            $function = strtolower($node->name->toString());
            if (in_array($function, ['mysqli_query', 'mysqli_real_query', 'mysqli_multi_query', 'mysqli_prepare'], true)) {
                return $this->argument($node->args, 1, 'query');
            }
        }

        if (!$node instanceof MethodCall || !$node->name instanceof Identifier) {
            return null;
        }

        $method = strtolower($node->name->toString());
        $receiver = $scope->getType($node->var);
        if (in_array($method, ['query', 'exec', 'prepare'], true)
            && (new ObjectType(\PDO::class))->isSuperTypeOf($receiver)->yes()
        ) {
            // PDO uses a different parameter name for exec()
            return $this->argument($node->args, 0, $method === 'exec' ? 'statement' : 'query');
        }
        if (in_array($method, ['query', 'real_query', 'multi_query', 'prepare'], true)
            && (new ObjectType(\mysqli::class))->isSuperTypeOf($receiver)->yes()
        ) {
            return $this->argument($node->args, 0, 'query');
        }

        return null;
    }

    /** @param array<Arg|ArgPlaceholder|VariadicPlaceholder> $arguments */
    private function argument(array $arguments, int $position, string $name): ?Expr
    {
        // Prefer a named query argument. Otherwise, use its positional index
        $positional = 0;
        foreach ($arguments as $argument) {
            if (!$argument instanceof Arg) {
                continue;
            }
            if ($argument->name !== null && strtolower($argument->name->toString()) === $name) {
                return $argument->value;
            }
            if ($argument->name === null && $positional++ === $position) {
                return $argument->value;
            }
        }

        return null;
    }
}
