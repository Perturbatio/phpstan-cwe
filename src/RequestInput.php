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
    /**
     * The optional callback checks local variable facts. A collector can instead
     * record each variable name and return false for later assignment resolution.
     * HTML escapes and numeric casts stop the scan before this callback is used.
     *
     * @param (callable(string): bool)|null $isAssignedInput
     */
    public static function inHtml(
        Node $node,
        Scope $scope,
        ReflectionProvider $reflectionProvider,
        ?callable $isAssignedInput = null,
    ): bool {
        $laravelRequestInput = new LaravelRequestInput($reflectionProvider);

        return self::contains($node, static function (FuncCall $call) use ($scope, $reflectionProvider): bool {
            if (!$call->name instanceof Name || count($call->args) !== 1
                || (!$call->name instanceof FullyQualified && $scope->getNamespace() !== null)
            ) {
                return false;
            }
            $function = $reflectionProvider->resolveFunctionName($call->name, $scope);

            return $function !== null && in_array(strtolower($function), ['htmlspecialchars', 'htmlentities'], true);
        }, static fn (Node $source): bool => $laravelRequestInput->isInput($source, $scope), $isAssignedInput);
    }

    public static function inSql(
        Node $node,
        ?Scope $scope = null,
        ?ReflectionProvider $reflectionProvider = null,
    ): bool {
        if ($scope === null || $reflectionProvider === null) {
            return self::contains($node, null);
        }

        $laravelRequestInput = new LaravelRequestInput($reflectionProvider);

        return self::contains($node, null, static fn (Node $source): bool => $laravelRequestInput->isInput($source, $scope));
    }

    /**
     * @param (callable(FuncCall): bool)|null $isSafeHtmlEscape
     * @param (callable(Node): bool)|null $isAdditionalRequestInput
     * @param (callable(string): bool)|null $isAssignedInput
     */
    private static function contains(
        Node $node,
        ?callable $isSafeHtmlEscape,
        ?callable $isAdditionalRequestInput = null,
        ?callable $isAssignedInput = null,
    ): bool {
        if ($node instanceof Variable && in_array($node->name, ['_GET', '_POST', '_COOKIE', '_REQUEST'], true)) {
            return true;
        }

        if ($node instanceof Variable && is_string($node->name) && $isAssignedInput !== null) {
            return $isAssignedInput($node->name);
        }

        // A number cannot add HTML code or SQL syntax.
        if ($node instanceof Int_ || $node instanceof Double) {
            return false;
        }

        // Only the default call to a real HTML escape function is safe here.
        if ($isSafeHtmlEscape !== null && $node instanceof FuncCall && $isSafeHtmlEscape($node)) {
            return false;
        }

        if ($isAdditionalRequestInput !== null && $isAdditionalRequestInput($node)) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node && self::contains($child, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput)) {
                return true;
            }
            if (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node && self::contains($item, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
