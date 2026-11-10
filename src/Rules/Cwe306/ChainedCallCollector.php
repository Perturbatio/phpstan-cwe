<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe306;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\TypeUtils;

/**
 * @phpstan-type CallFact array{start: int, end: int, method: string, candidates: list<array{string, string}>, complete: bool}
 * @implements Collector<Expr, CallFact|null>
 */
final class ChainedCallCollector implements Collector
{
    public function getNodeType(): string
    {
        return Expr::class;
    }

    public function processNode(Node $node, Scope $scope): ?array
    {
        if ((!$node instanceof Expr\MethodCall && !$node instanceof Expr\NullsafeMethodCall)
            || !$node->var instanceof Expr\CallLike || !$node->name instanceof Identifier
            || $node->isFirstClassCallable()
        ) {
            return null;
        }

        $type = $scope->getType($node->var);
        $method = $node->name->toString();
        $candidates = [];
        foreach (TypeUtils::flattenTypes($type) as $alternative) {
            foreach ($alternative->getObjectClassReflections() as $class) {
                if ($class->hasMethod($method)) {
                    $declaringClass = $class->getMethod($method, $scope)->getDeclaringClass()->getName();
                    $candidates[] = [$class->getName() . '::' . $method, $declaringClass . '::' . $method];
                }
            }
        }
        if ($candidates === []) {
            return null;
        }

        return [
            'start' => $node->getStartFilePos(),
            'end' => $node->getEndFilePos(),
            'method' => $method,
            'candidates' => $candidates,
            'complete' => count($candidates) === 1 && $type->isObject()->yes() && $type->hasMethod($method)->yes(),
        ];
    }
}
