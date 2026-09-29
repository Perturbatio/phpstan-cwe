<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PhpParser\Node;
use PhpParser\Node\Expr\Cast\Double;
use PhpParser\Node\Expr\Cast\Int_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;

final class RequestInput
{
    public static function inHtml(Node $node, Scope $scope, ReflectionProvider $reflectionProvider): bool
    {
        return self::contains($node, static function (FuncCall $call) use ($scope, $reflectionProvider): bool {
            return $call->name instanceof Name
                && count($call->args) === 1
                && ($call->name instanceof FullyQualified || $scope->getNamespace() === null)
                && in_array(
                    strtolower($reflectionProvider->resolveFunctionName($call->name, $scope) ?? ''),
                    ['htmlspecialchars', 'htmlentities'],
                    true,
                );
        });
    }

    public static function inSql(Node $node): bool
    {
        return self::contains($node, null);
    }

    /** @param (callable(FuncCall): bool)|null $isSafeHtmlEscape */
    private static function contains(Node $node, ?callable $isSafeHtmlEscape): bool
    {
        if ($node instanceof Variable && in_array($node->name, ['_GET', '_POST', '_COOKIE', '_REQUEST'], true)) {
            return true;
        }

        // A number cannot add HTML code or SQL syntax.
        if ($node instanceof Int_ || $node instanceof Double) {
            return false;
        }

        // Only the default call to a real HTML escape function is safe here.
        if ($isSafeHtmlEscape !== null && $node instanceof FuncCall && $isSafeHtmlEscape($node)) {
            return false;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node && self::contains($child, $isSafeHtmlEscape)) {
                return true;
            }
            if (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node && self::contains($item, $isSafeHtmlEscape)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
