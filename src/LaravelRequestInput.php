<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\ObjectType;
use PHPStan\Type\TypeCombinator;

final class LaravelRequestInput
{
    public function __construct(private readonly ReflectionProvider $reflectionProvider)
    {
    }

    public function isInput(Node $node, Scope $scope): bool
    {
        if ($node instanceof Expr\FuncCall) {
            return $this->isRequestHelper($node, $scope) && $node->args !== [];
        }

        if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall) {
            return !$node->isFirstClassCallable()
                && $node->name instanceof Identifier
                && in_array(strtolower($node->name->toString()), [
                    'input', 'get', 'query', 'post', 'cookie', 'header', 'server',
                    'all', 'only', 'except', 'json', 'collect', 'string', 'str',
                    'route', 'validated', 'safe', 'bearertoken', 'getcontent',
                ], true)
                && $this->isRequestObject($node->var, $scope);
        }

        if ($node instanceof Expr\PropertyFetch || $node instanceof Expr\NullsafePropertyFetch
            || $node instanceof Expr\ArrayDimFetch
        ) {
            return $this->isRequestObject($node->var, $scope);
        }

        return false;
    }

    private function isRequestObject(Expr $expression, Scope $scope): bool
    {
        if ($expression instanceof Expr\FuncCall && $this->isRequestHelper($expression, $scope)
            && $expression->args === []
        ) {
            return true;
        }

        return (new ObjectType('Illuminate\Http\Request'))
            ->isSuperTypeOf(TypeCombinator::removeNull($scope->getType($expression)))->yes();
    }

    private function isRequestHelper(Expr\FuncCall $call, Scope $scope): bool
    {
        if (!$call->name instanceof Name || $call->isFirstClassCallable()) {
            return false;
        }

        $function = $this->reflectionProvider->resolveFunctionName($call->name, $scope);

        return $function !== null && strtolower($function) === 'request';
    }
}
