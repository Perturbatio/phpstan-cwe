<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;

final class LaravelRouteParameters
{
    /**
     * @return list<array{variable: string, offset: int}>
     */
    public static function fromCall(Expr\StaticCall $call, Scope $scope): array
    {
        if (!$call->class instanceof Name || !$call->name instanceof Identifier
            || strtolower($scope->resolveName($call->class)) !== 'illuminate\\support\\facades\\route'
            || $call->isFirstClassCallable()
        ) {
            return [];
        }

        $method = strtolower($call->name->toString());
        if (!in_array($method, ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match'], true)) {
            return [];
        }

        $uri = null;
        $action = null;
        $uriPosition = $method === 'match' ? 1 : 0;
        foreach ($call->getArgs() as $position => $argument) {
            if ($argument->unpack) {
                return [];
            }
            $name = $argument->name?->toString();
            if ($name === 'uri' || ($name === null && $position === $uriPosition)) {
                $uri = $argument->value;
            } elseif ($name === 'action' || ($name === null && $position === $uriPosition + 1)) {
                $action = $argument->value;
            }
        }
        if (!$uri instanceof String_ || (!$action instanceof Expr\Closure && !$action instanceof Expr\ArrowFunction)) {
            return [];
        }
        preg_match_all('/\{([a-zA-Z_][a-zA-Z0-9_]*)(?::[^}?]+)?\??\}/', $uri->value, $matches);
        $names = $matches[1];
        if ($names === []) {
            return [];
        }

        $parameters = [];
        $remaining = count($names);
        foreach ($action->params as $parameter) {
            if (!$parameter->var instanceof Expr\Variable || !is_string($parameter->var->name)) {
                continue;
            }
            $namedParameter = in_array($parameter->var->name, $names, true);
            $isScalarParameter = !$parameter->type instanceof Name;
            if ($namedParameter || ($remaining > 0 && $isScalarParameter)) {
                $parameters[] = ['variable' => $parameter->var->name, 'offset' => $parameter->getStartTokenPos()];
                $remaining = max(0, $remaining - 1);
            }
        }

        return $parameters;
    }
}
