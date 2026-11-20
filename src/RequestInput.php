<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PhpParser\Node;
use PhpParser\Node\Expr\Cast\Double;
use PhpParser\Node\Expr\Cast\Int_;
use PhpParser\Node\Expr\ArrowFunction;
use PhpParser\Node\Expr\Closure;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\Print_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Return_;
use PHPStan\Analyser\Scope;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\Constant\ConstantIntegerType;

final class RequestInput
{
    /**
     * The optional callback checks local variable facts. A collector can instead
     * record each variable name and return false for later assignment resolution.
     * HTML escapes and numeric casts stop the scan before this callback is used.
     * The scan checks return expressions of directly invoked anonymous functions.
     * It follows captured arrow variables through the optional callback.
     *
     * @param (callable(string): bool)|null $isAssignedInput
     * @param (callable(string): bool)|null $isCalledInput
     */
    public static function inHtml(
        Node $node,
        Scope $scope,
        ReflectionProvider $reflectionProvider,
        ?callable $isAssignedInput = null,
        ?callable $isCalledInput = null,
    ): bool {
        $laravelRequestInput = new LaravelRequestInput($reflectionProvider);

        return self::contains($node, static function (FuncCall $call) use ($scope, $reflectionProvider): bool {
            if (!$call->name instanceof Name || $call->isFirstClassCallable()
                || (!$call->name instanceof FullyQualified && $scope->getNamespace() !== null)
            ) {
                return false;
            }
            $function = $reflectionProvider->resolveFunctionName($call->name, $scope);

            return $function !== null
                && in_array(strtolower($function), ['htmlspecialchars', 'htmlentities'], true)
                && self::hasSafeHtmlArguments($call, $scope);
        }, static fn (Node $source): bool => $laravelRequestInput->isInput($source, $scope), $isAssignedInput, true, $isCalledInput);
    }

    private static function hasSafeHtmlArguments(FuncCall $call, Scope $scope): bool
    {
        $arguments = [];
        $names = ['string', 'flags', 'encoding', 'double_encode'];
        foreach ($call->getArgs() as $index => $argument) {
            if ($argument->unpack) {
                return false;
            }
            $name = $argument->name?->toString() ?? ($names[$index] ?? '');
            if (!in_array($name, $names, true) || isset($arguments[$name])) {
                return false;
            }
            $arguments[$name] = $argument->value;
        }
        if (!isset($arguments['string'])) {
            return false;
        }
        if (isset($arguments['flags'])) {
            $flags = $scope->getType($arguments['flags']);
            if (!$flags instanceof ConstantIntegerType || ($flags->getValue() & ENT_QUOTES) !== ENT_QUOTES) {
                return false;
            }
        }
        if (isset($arguments['encoding'])) {
            $encoding = $scope->getType($arguments['encoding']);
            $values = $encoding->getConstantStrings();
            if (!$encoding->isConstantValue()->yes() || count($values) !== 1 || strcasecmp($values[0]->getValue(), 'UTF-8') !== 0) {
                return false;
            }
        }

        return true;
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
     * @param (callable(string): bool)|null $isCalledInput
     */
    private static function contains(
        Node $node,
        ?callable $isSafeHtmlEscape,
        ?callable $isAdditionalRequestInput = null,
        ?callable $isAssignedInput = null,
        bool $skipAnonymousFunctions = false,
        ?callable $isCalledInput = null,
    ): bool {
        if ($skipAnonymousFunctions && $node instanceof FuncCall
            && $node->name instanceof Variable && is_string($node->name->name) && !$node->isFirstClassCallable()
        ) {
            if ($isCalledInput !== null && $isCalledInput($node->name->name)) {
                return true;
            }
            foreach ($node->getArgs() as $argument) {
                if (self::contains($argument, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput, true, $isCalledInput)) {
                    return true;
                }
            }

            return false;
        }

        if ($skipAnonymousFunctions && $node instanceof FuncCall
            && ($node->name instanceof Closure || $node->name instanceof ArrowFunction)
        ) {
            if ($node->isFirstClassCallable()) {
                return false;
            }

            $parameters = [];
            foreach ($node->name->params as $parameter) {
                if ($parameter->var instanceof Variable && is_string($parameter->var->name)) {
                    $parameters[] = $parameter->var->name;
                }
            }
            $capturedInput = $isAssignedInput === null ? null : static fn (string $variable): bool => !in_array($variable, $parameters, true) && $isAssignedInput($variable);
            $capturedCall = $isCalledInput === null ? null : static fn (string $variable): bool => !in_array($variable, $parameters, true) && $isCalledInput($variable);
            $hasReturnedInput = $node->name instanceof ArrowFunction
                ? self::contains($node->name->expr, $isSafeHtmlEscape, $isAdditionalRequestInput, $capturedInput, true, $capturedCall)
                : self::containsReturnedHtmlInput($node->name->stmts, $isSafeHtmlEscape, $isAdditionalRequestInput);
            if ($hasReturnedInput) {
                return true;
            }
            foreach ($node->args as $argument) {
                if (self::contains($argument, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput, true, $isCalledInput)) {
                    return true;
                }
            }

            return false;
        }

        if ($skipAnonymousFunctions && ($node instanceof Closure || $node instanceof ArrowFunction)) {
            return false;
        }

        if ($skipAnonymousFunctions && $node instanceof Print_) {
            return false;
        }

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

        if ($isSafeHtmlEscape !== null && $node instanceof FuncCall && $isSafeHtmlEscape($node)) {
            return false;
        }

        if ($isAdditionalRequestInput !== null && $isAdditionalRequestInput($node)) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node && self::contains($child, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput, $skipAnonymousFunctions, $isCalledInput)) {
                return true;
            }
            if (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node && self::contains($item, $isSafeHtmlEscape, $isAdditionalRequestInput, $isAssignedInput, $skipAnonymousFunctions, $isCalledInput)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param array<Node> $nodes
     * @param (callable(FuncCall): bool)|null $isSafeHtmlEscape
     * @param (callable(Node): bool)|null $isAdditionalRequestInput
     */
    private static function containsReturnedHtmlInput(
        array $nodes,
        ?callable $isSafeHtmlEscape,
        ?callable $isAdditionalRequestInput,
    ): bool {
        foreach ($nodes as $node) {
            if ($node instanceof Node\FunctionLike || $node instanceof ClassLike) {
                continue;
            }
            if ($node instanceof Return_) {
                if ($node->expr !== null && self::contains($node->expr, $isSafeHtmlEscape, $isAdditionalRequestInput, null, true)) {
                    return true;
                }
                continue;
            }
            foreach ($node->getSubNodeNames() as $name) {
                $child = $node->$name;
                if ($child instanceof Node && self::containsReturnedHtmlInput([$child], $isSafeHtmlEscape, $isAdditionalRequestInput)) {
                    return true;
                }
                if (is_array($child)) {
                    foreach ($child as $item) {
                        if ($item instanceof Node && self::containsReturnedHtmlInput([$item], $isSafeHtmlEscape, $isAdditionalRequestInput)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }
}
