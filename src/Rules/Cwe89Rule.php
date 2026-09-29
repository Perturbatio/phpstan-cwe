<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules;

use Perturbatio\PhpstanCwe\CweReport;
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
use PHPStan\Rules\Rule;
use PHPStan\Type\ObjectType;

/** @implements Rule<Node> */
final class Cwe89Rule implements Rule
{
    private const SEVERITY = 'high';
    private const PROBABILITY = 80;

    public function __construct(private readonly int $minProbability = 0)
    {
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

        // Check query text before the call. Bound values are not query text.
        $query = $this->getQuery($node, $scope);
        if ($query === null || !RequestInput::inSql($query)) {
            return [];
        }

        return [CweReport::make(89, 'Request input is used in a SQL query. Use a bound parameter.', self::SEVERITY, self::PROBABILITY)];
    }

    private function getQuery(Node $node, Scope $scope): ?Expr
    {
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
        // A named argument can put the query at a new position.
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
