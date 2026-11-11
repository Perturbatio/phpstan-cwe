<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe306;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeFinder;

/**
 * Static route and call analysis. Unknown calls do not prove that a control is absent.
 *
 * @phpstan-type CallableBody array{node: Stmt\ClassMethod|Stmt\Function_, class: string|null, symbol: string}
 * @phpstan-type Operation array{operation: string, operationLine: int}
 * @phpstan-type Finding array{file: string, line: int, operation: string, operationLine: int, probability: int}
 * @phpstan-type ReceiverType string|array{containerClass: string}
 * @phpstan-import-type CallFact from ChainedCallCollector
 */
final class LaravelAuthenticationScanner
{
    private CriticalOperationMatcher $criticalOperations;

    /** @var array<string, CallableBody> */
    private array $callables = [];

    /** @var array<string, Stmt\Class_> */
    private array $classes = [];

    /** @var list<Finding> */
    private array $findings = [];

    /** @var array<int, CallFact> */
    private array $chainedCalls = [];

    /**
     * Global middleware must be supplied from the application's effective configuration.
     * Null means that this part of the request path is unknown.
     *
     * @param list<string> $criticalOperations
     * @param array<string, string> $middlewareAliases
     * @param list<string>|null $globalMiddleware
     */
    public function __construct(
        array $criticalOperations = [],
        private readonly array $middlewareAliases = [],
        private readonly ?array $globalMiddleware = null,
    ) {
        $this->criticalOperations = new CriticalOperationMatcher($criticalOperations);
    }

    public function hasCriticalOperations(): bool
    {
        return $this->criticalOperations->hasCriticalOperations();
    }

    /**
     * @param array<string, array<Stmt>> $files
     * @param array<string, list<CallFact|null>> $callFacts
     * @return list<Finding>
     */
    public function scan(array $files, array $callFacts = []): array
    {
        // Build the function and class lists before checking routes.
        // A route can call code in a file that appears later in the input.
        $this->callables = [];
        $this->classes = [];
        $this->findings = [];
        $this->chainedCalls = [];
        foreach ($files as $file => $nodes) {
            $facts = [];
            foreach ($callFacts[$file] ?? [] as $fact) {
                if ($fact !== null) {
                    $facts[$fact['start'] . ':' . $fact['end']] = $fact;
                }
            }
            foreach ((new NodeFinder())->findInstanceOf($nodes, Expr\CallLike::class) as $call) {
                $fact = $facts[$call->getStartFilePos() . ':' . $call->getEndFilePos()] ?? null;
                if ($fact !== null) {
                    $this->chainedCalls[spl_object_id($call)] = $fact;
                }
            }
            $traverser = new NodeTraverser(new NameResolver());
            $files[$file] = $traverser->traverse($nodes);
            $this->index($files[$file]);
        }
        foreach ($files as $file => $nodes) {
            $this->routes($nodes, $file, [], [], null, false);
        }

        return $this->findings;
    }

    /** @param array<Node> $nodes */
    private function index(array $nodes): void
    {
        foreach ($nodes as $node) {
            if ($node instanceof Stmt\Namespace_) {
                $this->index($node->stmts);
            } elseif ($node instanceof Stmt\Class_ && $node->name !== null) {
                $class = ($node->namespacedName ?? $node->name)->toString();
                $this->classes[strtolower($class)] = $node;
                foreach ($node->getMethods() as $method) {
                    $symbol = $class . '::' . $method->name;
                    $this->callables[strtolower($symbol)] = ['node' => $method, 'class' => $class, 'symbol' => $symbol];
                }
            } elseif ($node instanceof Stmt\Function_) {
                $name = ($node->namespacedName ?? $node->name)->toString();
                $this->callables[strtolower($name)] = ['node' => $node, 'class' => null, 'symbol' => $name];
            }
        }
    }

    /**
     * @param array<Node> $nodes
     * @param list<string>|null $inheritedMiddleware
     * @param list<string>|null $inheritedExclusions
     * @param array{class: string|null}|null $inheritedController
     */
    private function routes(array $nodes, string $file, ?array $inheritedMiddleware, ?array $inheritedExclusions, ?array $inheritedController, bool $unknownNamespace): void
    {
        foreach ($nodes as $node) {
            if ($node instanceof Stmt\Namespace_) {
                $this->routes($node->stmts, $file, $inheritedMiddleware, $inheritedExclusions, $inheritedController, $unknownNamespace);
            } elseif ($node instanceof Stmt\Expression) {
                $this->route($node->expr, $file, $inheritedMiddleware, $inheritedExclusions, $inheritedController, $unknownNamespace);
            }
        }
    }

    /**
     * @param list<string>|null $inheritedMiddleware
     * @param list<string>|null $inheritedExclusions
     * @param array{class: string|null}|null $inheritedController
     */
    private function route(Expr $expression, string $file, ?array $inheritedMiddleware, ?array $inheritedExclusions, ?array $inheritedController, bool $unknownNamespace): void
    {
        // Read a chain such as Route::post(...)->middleware(...) from left to right.
        // This keeps the route action and its middleware in one request path.
        $calls = [];
        $base = $expression;
        while ($base instanceof Expr\MethodCall) {
            array_unshift($calls, $base);
            $base = $base->var;
        }
        if (!$base instanceof Expr\StaticCall || !$base->class instanceof Name
            || !$this->isRouteFacade($base->class) || !$base->name instanceof Identifier
        ) {
            return;
        }
        array_unshift($calls, $base);
        foreach ($calls as $call) {
            if ($call->isFirstClassCallable()) {
                // This syntax creates a callable. It does not register a route.
                return;
            }
        }
        $middleware = $inheritedMiddleware;
        $excludedMiddleware = $inheritedExclusions;
        $controller = $inheritedController;
        $handler = null;
        $group = null;
        foreach ($calls as $call) {
            if (!$call->name instanceof Identifier) {
                // A dynamic method can change the controls. Do not assume an empty list.
                $middleware = null;
                $excludedMiddleware = null;
                $unknownNamespace = true;
                continue;
            }
            $method = strtolower($call->name->toString());
            if ($method === 'middleware') {
                $added = $this->strings($this->argument($call, 0, 'middleware'));
                $middleware = $middleware !== null && $added !== null ? [...$middleware, ...$added] : null;
            } elseif ($method === 'withoutmiddleware') {
                $removed = $this->strings($this->argument($call, 0, 'middleware'));
                $excludedMiddleware = $removed !== null && $excludedMiddleware !== null ? [...$excludedMiddleware, ...$removed] : null;
                if ($removed === null) {
                    $middleware = null;
                }
            } elseif ($method === 'controller') {
                $controller = ['class' => $this->controllerName($this->argument($call, 0, 'controller'))];
            } elseif ($method === 'group') {
                $group = $this->argument($call, 0, 'callback');
                if ($group instanceof Expr\Array_) {
                    $attributes = $group;
                    $group = $this->argument($call, 1, 'routes');
                    foreach ($attributes->items as $item) {
                        if ($item->key instanceof Scalar\String_ && $item->key->value === 'middleware') {
                            $added = $this->strings($item->value);
                            $middleware = $middleware !== null && $added !== null ? [...$middleware, ...$added] : null;
                        } elseif ($item->key instanceof Scalar\String_ && $item->key->value === 'controller') {
                            $controller = ['class' => $this->controllerName($item->value)];
                        } elseif ($item->key instanceof Scalar\String_ && $item->key->value === 'excluded_middleware') {
                            $removed = $this->strings($item->value);
                            $excludedMiddleware = $excludedMiddleware !== null && $removed !== null ? [...$excludedMiddleware, ...$removed] : null;
                        } elseif (!$item->key instanceof Scalar\String_ || !in_array($item->key->value, ['prefix', 'as', 'domain', 'where'], true)) {
                            $middleware = null;
                            if (!$item->key instanceof Scalar\String_ || $item->key->value === 'namespace') {
                                $unknownNamespace = true;
                            }
                            if (!$item->key instanceof Scalar\String_) {
                                $excludedMiddleware = null;
                            }
                        }
                    }
                }
            } elseif (in_array($method, ['get', 'post', 'put', 'patch', 'delete', 'options', 'any', 'match'], true)) {
                $handler = $this->argument($call, $method === 'match' ? 2 : 1, 'action');
            } elseif (!in_array($method, ['as', 'name', 'prefix', 'domain', 'where', 'wherenumber', 'whereslug'], true)) {
                $middleware = null;
                $unknownNamespace = true;
            }
        }
        if ($group instanceof Expr\Closure) {
            if ($unknownNamespace) {
                $controller = ['class' => null];
            }
            $this->routes($group->stmts, $file, $middleware, $excludedMiddleware, $controller, $unknownNamespace);
        } elseif ($handler !== null) {
            $this->checkRoute($handler, $file, $expression->getStartLine(), $middleware, $excludedMiddleware, $inheritedController);
        }
    }

    private function controllerName(?Expr $expression): ?string
    {
        if (!$expression instanceof Scalar\String_ && !$expression instanceof Expr\ClassConstFetch) {
            return null;
        }
        $values = $this->strings($expression);
        $name = $values[0] ?? null;
        if ($name === null || !preg_match('/^\\\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*(?:\\\\[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)*$/D', $name)
            || in_array(strtolower($name), ['self', 'static', 'parent'], true)
        ) {
            return null;
        }

        return ltrim($name, '\\');
    }

    private function isRouteFacade(Name $name): bool
    {
        $class = strtolower($name->toString());

        return $class === 'illuminate\\support\\facades\\route'
            || ($class === 'route' && !isset($this->classes['route']));
    }

    /** @return list<string>|null */
    private function strings(?Expr $expression): ?array
    {
        if ($expression instanceof Scalar\String_) {
            return [$expression->value];
        }
        if ($expression instanceof Expr\ClassConstFetch && $expression->class instanceof Name
            && $expression->name instanceof Identifier && strtolower($expression->name->toString()) === 'class'
        ) {
            return [$expression->class->toString()];
        }
        if ($expression instanceof Expr\Array_) {
            $strings = [];
            foreach ($expression->items as $item) {
                if ($item->unpack || $item->key !== null) {
                    return null;
                }
                $values = $this->strings($item->value);
                if ($values === null) {
                    return null;
                }
                array_push($strings, ...$values);
            }

            return $strings;
        }

        return null;
    }

    private function argument(Expr\CallLike $call, int $position, string $name): ?Expr
    {
        foreach ($call->getArgs() as $argument) {
            if ($argument->name?->toString() === $name) {
                return $argument->value;
            }
        }
        $argument = $call->getArgs()[$position] ?? null;

        return $argument instanceof Node\Arg && $argument->name === null ? $argument->value : null;
    }

    private function middlewareClass(string $middleware): string
    {
        // In auth:sanctum, auth selects the middleware and sanctum selects the guard.
        // Both auth and auth:sanctum can therefore require authentication.
        $name = explode(':', $middleware)[0];

        return $this->middlewareAliases[$name] ?? match ($name) {
            'auth' => 'Illuminate\Auth\Middleware\Authenticate',
            default => $name,
        };
    }

    /** @param list<string> $excludedMiddleware */
    private function isMiddlewareExcluded(string $middleware, array $excludedMiddleware): bool
    {
        $parts = explode(':', $middleware, 2);
        $class = $this->middlewareClass($middleware);
        foreach ($excludedMiddleware as $excluded) {
            $excludedParts = explode(':', $excluded, 2);
            $excludedClass = $this->middlewareClass($excluded);
            $resolvedExclusion = $excludedClass . (isset($excludedParts[1]) ? ':' . $excludedParts[1] : '');
            if ($resolvedExclusion === $class || (isset($parts[1]) && $resolvedExclusion === $class . ':' . $parts[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * True means authentication is required. False means the list is empty.
     * Null means the list is unknown or contains a control we cannot identify.
     *
     * @param array<int, string>|null $middleware
     */
    private function middlewareState(?array $middleware): ?bool
    {
        if ($middleware === null) {
            return null;
        }
        foreach ($middleware as $name) {
            if (strtolower($this->middlewareClass($name)) === 'illuminate\\auth\\middleware\\authenticate') {
                return true;
            }
        }

        return $middleware === [] ? false : null;
    }

    /**
     * @param list<string>|null $middleware
     * @param list<string>|null $excludedMiddleware
     * @param array{class: string|null}|null $controller
     */
    private function checkRoute(Expr $handler, string $file, int $line, ?array $middleware, ?array $excludedMiddleware, ?array $controller): void
    {
        $symbol = $this->handlerSymbol($handler, $controller);
        $body = $symbol === null ? null : $this->body($symbol);
        $controllerMiddleware = $body === null || $body['class'] === null
            ? []
            : $this->controllerMiddleware(explode('::', $symbol)[0], explode('::', $symbol)[1], []);
        // Route exclusions also apply to controller middleware, but not to global middleware.
        if ($middleware !== null && $excludedMiddleware !== null) {
            $middleware = array_filter($middleware, fn (string $name): bool => !$this->isMiddlewareExcluded($name, $excludedMiddleware));
        } else {
            $middleware = null;
        }
        if ($controllerMiddleware !== null && $excludedMiddleware !== null) {
            $controllerMiddleware = array_filter($controllerMiddleware, fn (string $name): bool => !$this->isMiddlewareExcluded($name, $excludedMiddleware));
        } else {
            $controllerMiddleware = null;
        }
        $routeState = $this->middlewareState($middleware);
        $globalState = $this->middlewareState($this->globalMiddleware);
        $controllerState = $this->middlewareState($controllerMiddleware);
        if ($routeState === true || $globalState === true || $controllerState === true) {
            return;
        }
        $complete = true;
        $operations = [];
        if ($handler instanceof Expr\Closure || $handler instanceof Expr\ArrowFunction) {
            $statements = $handler instanceof Expr\Closure ? $handler->stmts : [new Stmt\Return_($handler->expr)];
            $authenticated = $this->requestState($handler->params, false, [], $operations, $complete);
            if ($authenticated !== null) {
                $this->flow($statements, [$authenticated], $this->types($handler->params), [], $operations, $complete);
            }
        } elseif ($symbol !== null) {
            $this->invoke($symbol, false, [], $operations, $complete, $line, true);
        }
        // The route and critical operation give 40 points. Complete call analysis adds 20.
        // Resolved middleware and explicit global configuration add 25 and 15 points.
        // Unknown controls must not earn points for missing authentication.
        $probability = 40 + ($complete ? 20 : 0);
        if ($routeState === false && $globalState === false && $controllerState === false) {
            $probability += 40;
        }
        $seen = [];
        foreach ($operations as $operation) {
            // Report an operation once per route, even if several calls reach it.
            // A different route to the same operation must still be checked.
            if (isset($seen[$operation['operation']])) {
                continue;
            }
            $seen[$operation['operation']] = $operation;
            $this->findings[] = ['file' => $file, 'line' => $line, ...$operation, 'probability' => $probability];
        }
    }

    /** @param array{class: string|null}|null $controller */
    private function handlerSymbol(Expr $handler, ?array $controller): ?string
    {
        $values = $this->strings($handler);
        if ($values === null) {
            return null;
        }
        if (count($values) === 2) {
            return $values[0] . '::' . $values[1];
        }
        if (count($values) === 1) {
            if ($handler instanceof Scalar\String_ && !str_contains($values[0], '@') && $controller !== null) {
                $value = ltrim($values[0], '\\');
                if (isset($this->classes[strtolower($value)])) {
                    return $value . '::__invoke';
                }
                if (!preg_match('/^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$/D', $value) || $controller['class'] === null) {
                    return null;
                }

                return $controller['class'] . '::' . $value;
            }
            return str_replace('@', '::', $values[0]) . (str_contains($values[0], '@') ? '' : '::__invoke');
        }

        return null;
    }

    /**
     * Unsupported controller middleware declarations remain unknown.
     *
     * @param list<string> $visited
     * @return list<string>|null
     */
    private function controllerMiddleware(string $class, string $action, array $visited): ?array
    {
        $key = strtolower($class);
        if (in_array($key, $visited, true) || !isset($this->classes[$key])) {
            return $key === 'illuminate\\routing\\controller' ? [] : null;
        }
        $node = $this->classes[$key];
        if ($node->getMethod('middleware') !== null || $node->getTraitUses() !== []) {
            // Custom methods and traits can change how middleware is registered.
            return null;
        }
        $middleware = $node->extends === null ? [] : $this->controllerMiddleware($node->extends->toString(), $action, [...$visited, $key]);
        foreach ($node->getMethod('__construct')->stmts ?? [] as $statement) {
            if (!$statement instanceof Stmt\Expression) {
                return null;
            }
            $call = $statement->expr;
            $applies = true;
            // Check only() and except() against this action, not the whole controller.
            while ($call instanceof Expr\MethodCall && $call->name instanceof Identifier
                && in_array(strtolower($call->name->toString()), ['only', 'except'], true)
            ) {
                $actions = $this->strings($this->argument($call, 0, 'methods'));
                if ($actions === null) {
                    return null;
                }
                $matches = in_array($action, $actions, true);
                $applies = $applies && (strtolower($call->name->toString()) === 'only' ? $matches : !$matches);
                $call = $call->var;
            }
            if (!$call instanceof Expr\MethodCall || !$call->name instanceof Identifier
                || strtolower($call->name->toString()) !== 'middleware'
                || !$call->var instanceof Expr\Variable || $call->var->name !== 'this'
            ) {
                return null;
            }
            $added = $this->strings($this->argument($call, 0, 'middleware'));
            if ($added === null || $middleware === null) {
                return null;
            }
            if ($applies) {
                array_push($middleware, ...$added);
            }
        }

        return $middleware;
    }

    /** @return CallableBody|null */
    private function body(string $symbol): ?array
    {
        $visited = [];
        $symbol = strtolower($symbol);
        while (!isset($this->callables[$symbol])) {
            if (!str_contains($symbol, '::') || isset($visited[$symbol])) {
                return null;
            }
            $visited[$symbol] = $symbol;
            [$class, $method] = explode('::', $symbol);
            $parent = $this->classes[$class]->extends ?? null;
            if ($parent === null) {
                return null;
            }
            $symbol = strtolower($parent->toString()) . '::' . $method;
        }

        return $this->callables[$symbol];
    }

    /**
     * @param array<Node\Param> $parameters
     * @return array<string, string>
     */
    private function types(array $parameters, ?string $class = null): array
    {
        $types = $class === null ? [] : ['this' => $class];
        foreach ($parameters as $parameter) {
            if ($parameter->var instanceof Expr\Variable && is_string($parameter->var->name) && $parameter->type instanceof Name) {
                $types[$parameter->var->name] = $parameter->type->toString();
            }
        }

        return $types;
    }

    /**
     * @param list<string> $stack
     * @param list<Operation> $operations
     * @return bool|null Whether all normal returns require a user. Null means no normal return.
     */
    private function invoke(string $symbol, bool $authenticated, array $stack, array &$operations, bool &$complete, int $line, bool $entry = false): ?bool
    {
        $body = $this->body($symbol);
        $criticalOperation = $body === null
            ? $this->criticalOperations->match($symbol)
            : $this->criticalOperations->matchAny([$symbol, $body['symbol']]);
        if ($criticalOperation !== null && !$entry) {
            if (!$authenticated) {
                $operations[] = ['operation' => $criticalOperation, 'operationLine' => $line];
            }

            return $authenticated;
        }
        $key = strtolower($symbol);
        if (in_array($key, $stack, true) || count($stack) >= 16) {
            // Stop recursive or deep calls. A stopped scan is incomplete, not proof
            // that the remaining code has no authentication check.
            $complete = false;

            return $authenticated;
        }
        if ($body === null || $body['node']->stmts === null) {
            if ($criticalOperation !== null && !$authenticated) {
                $operations[] = ['operation' => $criticalOperation, 'operationLine' => $line];
            }
            $complete = false;

            return $authenticated;
        }
        $receiver = str_contains($symbol, '::') ? explode('::', $symbol)[0] : null;
        $types = $this->types($body['node']->params, $receiver);
        // self refers to the declaring class. $this can refer to a child instance.
        if ($body['class'] !== null) {
            $types['self'] = $body['class'];
        }
        if ($entry) {
            // Laravel resolves injected form requests before it calls the route action.
            $authenticated = $this->requestState($body['node']->params, $authenticated, [$key], $operations, $complete);
            if ($authenticated === null) {
                return null;
            }
        }
        if ($criticalOperation !== null) {
            if (!$authenticated) {
                $operations[] = ['operation' => $criticalOperation, 'operationLine' => $line];
            }

            return $authenticated;
        }
        $returns = [];
        $remaining = $this->flow($body['node']->stmts, [$authenticated], $types, [...$stack, $key], $operations, $complete, $returns);
        $returns = [...$returns, ...$remaining];

        // A helper enforces authentication only if every normal return requires a user.
        // A helper that only returns Auth::check() does not enforce its result.
        return $returns === [] ? null : !in_array(false, $returns, true);
    }

    /**
     * @param array<Node\Param> $parameters
     * @param list<string> $stack
     * @param list<Operation> $operations
     */
    private function requestState(array $parameters, bool $authenticated, array $stack, array &$operations, bool &$complete): ?bool
    {
        foreach ($parameters as $parameter) {
            if (!$parameter->type instanceof Name || !$this->isFormRequest($parameter->type->toString(), [])) {
                continue;
            }
            $request = $parameter->type->toString();
            // This hook runs before authorize(). Operations here cannot rely on
            // the authentication result that authorize() returns later.
            if ($this->body($request . '::prepareForValidation') !== null) {
                $enforced = $this->invoke($request . '::prepareForValidation', $authenticated, $stack, $operations, $complete, $parameter->getStartLine());
                if ($enforced === null) {
                    return null;
                }
                $authenticated = $enforced;
            }
            $authorization = $this->body($request . '::authorize');
            if ($authorization === null) {
                continue;
            }
            $enforced = $this->invoke($request . '::authorize', $authenticated, $stack, $operations, $complete, $parameter->getStartLine());
            if ($enforced === null) {
                return null;
            }
            $authenticated = $enforced;
            // Custom lifecycle methods can bypass the normal denial of a request.
            // Do not accept the authorize() result as a guarantee in that case.
            if ($this->body($request . '::failedAuthorization') !== null
                || $this->body($request . '::passesAuthorization') !== null
                || $this->body($request . '::validateResolved') !== null
            ) {
                $complete = false;
                continue;
            }
            $statements = $authorization['node']->stmts ?? [];
            if (count($statements) === 1 && $statements[0] instanceof Stmt\Return_) {
                $result = $statements[0]->expr;
                if ($result instanceof Expr\ConstFetch && strtolower($result->name->toString()) === 'false') {
                    return null;
                }
                $authenticated = $authenticated || ($result !== null && $this->predicate($result, ['this' => $request]) === true);
            } else {
                $complete = false;
            }
        }

        return $authenticated;
    }

    /** @param list<string> $visited */
    private function isFormRequest(string $class, array $visited): bool
    {
        if (strtolower($class) === 'illuminate\\foundation\\http\\formrequest') {
            return true;
        }
        if (in_array(strtolower($class), $visited, true)) {
            return false;
        }
        $parent = $this->classes[strtolower($class)]->extends ?? null;

        return $parent !== null && $this->isFormRequest($parent->toString(), [...$visited, strtolower($class)]);
    }

    /**
     * Each state describes one path that can continue: true requires a user;
     * false does not. An empty list means no path can continue.
     * Keep normal returns separate so a return stops this function, not its caller.
     *
     * @param array<Stmt> $statements
     * @param list<bool> $states
     * @param array<string, ReceiverType> $types
     * @param list<string> $stack
     * @param list<Operation> $operations
     * @param list<bool> $returns
     * @return list<bool>
     */
    private function flow(array $statements, array $states, array $types, array $stack, array &$operations, bool &$complete, array &$returns = []): array
    {
        foreach ($statements as $statement) {
            if ($states === []) {
                return [];
            }
            if ($statement instanceof Stmt\If_) {
                $this->forgetWrittenTypes($statement->cond, $types);
                $predicate = $this->predicate($statement->cond, $types);
                $this->expressions($statement->cond, $states, $types, $stack, $operations, $complete);
                $trueStates = [];
                $falseStates = [];
                foreach ($states as $state) {
                    $trueStates[] = $state || $predicate === true;
                    $falseStates[] = $state || $predicate === false;
                }
                $then = $this->flow($statement->stmts, $trueStates, $types, $stack, $operations, $complete, $returns);
                $else = $this->flow($statement->else->stmts ?? [], $falseStates, $types, $stack, $operations, $complete, $returns);
                if ($statement->elseifs !== []) {
                    $complete = false;
                    foreach ($statement->elseifs as $elseif) {
                        $this->expressions($elseif, $states, $types, $stack, $operations, $complete);
                    }
                    $else = [...$else, ...$states];
                }
                // Keep both possible paths. One protected branch does not protect
                // an operation that is also reachable through the other branch.
                $states = array_values(array_unique([...$then, ...$else], SORT_REGULAR));
                // Branch-local assignments do not establish a type on every path.
                $this->forgetWrittenTypes($statement, $types);
            } elseif ($statement instanceof Stmt\Expression || $statement instanceof Stmt\Return_) {
                $assignment = $statement->expr;
                $isDirectAssignment = $assignment instanceof Expr\Assign
                    && $assignment->var instanceof Expr\Variable && is_string($assignment->var->name);
                $this->forgetWrittenTypes($isDirectAssignment ? $assignment->expr : $statement, $types);
                if ($statement->expr !== null) {
                    $this->expressions($statement->expr, $states, $types, $stack, $operations, $complete);
                }
                // Expression analysis removes paths stopped by throw or exit.
                // Only the remaining paths can return to the caller.
                if ($statement instanceof Stmt\Return_) {
                    array_push($returns, ...$states);
                }
                if ($statement instanceof Stmt\Return_) {
                    $states = [];
                }
                $this->forgetWrittenTypes($statement, $types);
                if ($isDirectAssignment && $assignment->expr instanceof Expr\New_
                    && $assignment->expr->class instanceof Name
                    && !$assignment->expr->class->isSpecialClassName() && $states !== []
                ) {
                    // Save the class only after constructor arguments can execute.
                    $types[$assignment->var->name] = $assignment->expr->class->toString();
                } elseif ($isDirectAssignment && $states !== []) {
                    $containerClass = $this->containerClass($assignment->expr);
                    if ($containerClass !== null) {
                        // A binding can replace the requested class. Keep this fact separate.
                        $types[$assignment->var->name] = ['containerClass' => $containerClass];
                    }
                }
            } else {
                $complete = false;
                $this->forgetWrittenTypes($statement, $types);
                // Inspect unsupported statements for operations, but do not use
                // their control flow to claim that later code requires a user.
                $unknownStates = $states;
                $this->expressions($statement, $unknownStates, $types, $stack, $operations, $complete);
            }
        }

        return $states;
    }

    /** @param array<string, ReceiverType> $types */
    private function forgetWrittenTypes(Node $node, array &$types): void
    {
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction
            || $node instanceof Stmt\ClassLike || $node instanceof Stmt\Function_
        ) {
            return;
        }
        if ($node instanceof Expr\AssignRef) {
            // References can change more than the assignment target.
            $types = [];
            return;
        }
        if ($node instanceof Expr\Assign || $node instanceof Expr\AssignOp
            || $node instanceof Expr\PreInc || $node instanceof Expr\PostInc
            || $node instanceof Expr\PreDec || $node instanceof Expr\PostDec
        ) {
            $this->forgetTargetType($node->var, $types);
        }
        if ($node instanceof Stmt\Unset_) {
            foreach ($node->vars as $variable) {
                $this->forgetTargetType($variable, $types);
            }
        }
        if ($node instanceof Stmt\Foreach_) {
            $this->forgetTargetType($node->valueVar, $types);
            if ($node->keyVar !== null) {
                $this->forgetTargetType($node->keyVar, $types);
            }
        }
        foreach ($node->getSubNodeNames() as $name) {
            $children = $node->$name;
            foreach (is_array($children) ? $children : [$children] as $child) {
                if ($child instanceof Node) {
                    $this->forgetWrittenTypes($child, $types);
                }
            }
        }
    }

    /** @param array<string, ReceiverType> $types */
    private function forgetTargetType(Expr $target, array &$types): void
    {
        if ($target instanceof Expr\Variable) {
            if (is_string($target->name)) {
                unset($types[$target->name]);
            } else {
                $types = [];
            }
        } elseif ($target instanceof Expr\List_) {
            foreach ($target->items as $item) {
                if ($item !== null) {
                    $this->forgetTargetType($item->value, $types);
                }
            }
        }
    }

    /**
     * @param list<bool> $states
     * @param array<string, ReceiverType> $types
     * @param list<string> $stack
     * @param list<Operation> $operations
     */
    private function expressions(Node $node, array &$states, array $types, array $stack, array &$operations, bool &$complete): void
    {
        if ($states === []) {
            return;
        }
        if ($node instanceof Expr\Throw_ || $node instanceof Expr\Exit_) {
            if ($node->expr !== null) {
                $this->expressions($node->expr, $states, $types, $stack, $operations, $complete);
            }
            $states = [];
        }
        if ($node instanceof Expr\Ternary || $node instanceof Expr\BinaryOp\BooleanAnd || $node instanceof Expr\BinaryOp\BooleanOr
            || $node instanceof Expr\BinaryOp\LogicalAnd || $node instanceof Expr\BinaryOp\LogicalOr || $node instanceof Expr\BinaryOp\Coalesce
        ) {
            // These expressions do not always evaluate both sides.
            // Apply the authentication fact only to the side that requires it.
            $condition = $node instanceof Expr\Ternary ? $node->cond : $node->left;
            $this->expressions($condition, $states, $types, $stack, $operations, $complete);
            $predicate = $this->predicate($condition, $types);
            if ($node instanceof Expr\BinaryOp\Coalesce && $predicate !== null && !$this->isIdentityRead($condition, $types)) {
                return;
            }
            $trueStates = array_map(static fn (bool $state): bool => $state || $predicate === true, $states);
            $falseStates = array_map(static fn (bool $state): bool => $state || $predicate === false, $states);
            if ($node instanceof Expr\Ternary) {
                if ($node->if !== null) {
                    $this->expressions($node->if, $trueStates, $types, $stack, $operations, $complete);
                }
                $this->expressions($node->else, $falseStates, $types, $stack, $operations, $complete);
            } elseif ($node instanceof Expr\BinaryOp\BooleanAnd || $node instanceof Expr\BinaryOp\LogicalAnd) {
                $this->expressions($node->right, $trueStates, $types, $stack, $operations, $complete);
            } else {
                $this->expressions($node->right, $falseStates, $types, $stack, $operations, $complete);
            }
            $states = array_values(array_unique([...$trueStates, ...$falseStates], SORT_REGULAR));

            return;
        }
        if ($node instanceof Expr\Include_) {
            $complete = false;
        }
        if ($node instanceof Expr\Match_) {
            $complete = false;
            $this->expressions($node->cond, $states, $types, $stack, $operations, $complete);
            $remaining = [];
            foreach ($node->arms as $arm) {
                $armStates = $states;
                $this->expressions($arm->body, $armStates, $types, $stack, $operations, $complete);
                array_push($remaining, ...$armStates);
            }
            $states = array_values(array_unique($remaining, SORT_REGULAR));

            return;
        }
        if ($node instanceof Expr\Closure || $node instanceof Expr\ArrowFunction) {
            $complete = false;

            // Creating a closure does not execute its body.
            return;
        }
        if ($node instanceof Expr\CallLike) {
            $isControl = $this->predicate($node, $types) !== null || $this->isIdentityRead($node, $types);
            if ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall) {
                if ($isControl && $node->var instanceof Expr\FuncCall) {
                    foreach ($node->var->getArgs() as $argument) {
                        $this->expressions($argument->value, $states, $types, $stack, $operations, $complete);
                    }
                } elseif (!$isControl) {
                    $this->expressions($node->var, $states, $types, $stack, $operations, $complete);
                }
            }
            if ($node->isFirstClassCallable()) {
                $complete = false;

                return;
            }
            $nullableStates = $states;
            // PHP evaluates arguments before it calls the function or method.
            // A check inside that call cannot protect an operation in an argument.
            foreach ($node->getArgs() as $argument) {
                $this->expressions($argument->value, $states, $types, $stack, $operations, $complete);
            }
            $executingStates = $states;
            if ($node instanceof Expr\NullsafeMethodCall) {
                $states = array_values(array_unique([...$states, ...$nullableStates], SORT_REGULAR));
            }
            if ($states === []) {
                return;
            }
            if ($this->authMethod($node, $types) === 'logout') {
                // An earlier authentication check no longer protects this path.
                $states = [false];

                return;
            }
            $containerSymbol = $this->containerCallSymbol($node, $types);
            if ($containerSymbol !== null) {
                $complete = false;
                // Only a selected operation can be checked. Do not execute a
                // requested class body as if the container binding were known.
                $criticalOperation = $this->criticalOperations->match($containerSymbol);
                if ($criticalOperation !== null && in_array(false, $states, true)) {
                    $operations[] = ['operation' => $criticalOperation, 'operationLine' => $node->getStartLine()];
                }
            } elseif (!$isControl) {
                $fact = $this->chainedCalls[spl_object_id($node)] ?? null;
                if ($fact !== null && ($node instanceof Expr\MethodCall || $node instanceof Expr\NullsafeMethodCall)
                    && $node->name instanceof Identifier && $fact['method'] === $node->name->toString()) {
                    // Receiver facts select operations. They cannot establish authentication.
                    $complete = false;
                    if (in_array(false, $executingStates, true)) {
                        foreach ($fact['candidates'] as $candidate) {
                            $criticalOperation = $this->criticalOperations->matchAny($candidate);
                            if ($criticalOperation !== null) {
                                $operations[] = ['operation' => $criticalOperation, 'operationLine' => $node->getStartLine()];
                            }
                        }
                    }

                    return;
                }
                $symbol = $this->callSymbol($node, $types);
                if ($symbol === null) {
                    $complete = false;
                } else {
                    $nextStates = [];
                    foreach ($states as $state) {
                        $enforced = $this->invoke($symbol, $state, $stack, $operations, $complete, $node->getStartLine());
                        if ($enforced !== null) {
                            $nextStates[] = $enforced;
                        }
                    }
                    $states = $nextStates;
                }
            }

            return;
        }
        foreach ($node->getSubNodeNames() as $name) {
            $child = $node->$name;
            if ($child instanceof Node) {
                if ($node instanceof Stmt) {
                    $branchStates = $states;
                    $this->expressions($child, $branchStates, $types, $stack, $operations, $complete);
                } else {
                    $this->expressions($child, $states, $types, $stack, $operations, $complete);
                }
            } elseif (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node) {
                        if ($node instanceof Stmt) {
                            $branchStates = $states;
                            $this->expressions($item, $branchStates, $types, $stack, $operations, $complete);
                        } else {
                            $this->expressions($item, $states, $types, $stack, $operations, $complete);
                        }
                    }
                }
            }
        }
    }

    private function containerClass(Expr $expression): ?string
    {
        $call = $expression;
        if ($call instanceof Expr\MethodCall && $call->name instanceof Identifier
            && strtolower($call->name->toString()) === 'make'
            && $call->var instanceof Expr\FuncCall && !$call->var->isFirstClassCallable()
            && $call->var->getArgs() === [] && $this->isAppHelper($call->var)
        ) {
            $arguments = $call;
        } elseif ($call instanceof Expr\FuncCall && $this->isAppHelper($call)) {
            $arguments = $call;
        } else {
            return null;
        }
        if ($arguments->isFirstClassCallable()) {
            return null;
        }
        foreach ($arguments->getArgs() as $argument) {
            if ($argument->unpack) {
                return null;
            }
        }
        $abstract = $this->argument($arguments, 0, 'abstract');
        if (!$abstract instanceof Expr\ClassConstFetch || !$abstract->class instanceof Name
            || $abstract->class->isSpecialClassName() || !$abstract->name instanceof Identifier
            || strtolower($abstract->name->toString()) !== 'class'
        ) {
            return null;
        }

        return $abstract->class->toString();
    }

    private function isAppHelper(Expr\FuncCall $call): bool
    {
        $symbol = $this->callSymbol($call, []);

        return $symbol !== null && strtolower($symbol) === 'app' && !isset($this->callables['app']);
    }

    /** @param array<string, ReceiverType> $types */
    private function containerCallSymbol(Expr\CallLike $call, array $types): ?string
    {
        if ($call instanceof Expr\MethodCall && $call->name instanceof Identifier
            && $call->var instanceof Expr\Variable && is_string($call->var->name)
        ) {
            $receiver = $types[$call->var->name] ?? null;
            if (is_array($receiver)) {
                return $receiver['containerClass'] . '::' . $call->name->toString();
            }
        }

        return null;
    }

    /** @param array<string, ReceiverType> $types */
    private function callSymbol(Expr\CallLike $call, array $types): ?string
    {
        if ($call instanceof Expr\FuncCall && $call->name instanceof Name) {
            $name = $call->name->toString();
            $fallback = $call->name->getAttribute('namespacedName');
            // PHP checks the current namespace before it falls back to a global function.
            // Do not match a global critical function when a local function replaces it.
            if ($fallback instanceof Name && (isset($this->callables[strtolower($fallback->toString())])
                || $this->criticalOperations->match($fallback->toString()) !== null)) {
                return $fallback->toString();
            }
            return $name;
        }
        if ($call instanceof Expr\StaticCall && $call->class instanceof Name && $call->name instanceof Identifier) {
            $class = $call->class->toString();
            if (in_array(strtolower($class), ['self', 'static'], true)) {
                $receiver = $types[strtolower($class) === 'self' ? 'self' : 'this'] ?? null;
                if (is_string($receiver)) {
                    $class = $receiver;
                }
            }

            return $class . '::' . $call->name->toString();
        }
        if ($call instanceof Expr\MethodCall && $call->name instanceof Identifier
            && $call->var instanceof Expr\Variable && is_string($call->var->name) && isset($types[$call->var->name])
            && is_string($types[$call->var->name])
        ) {
            return $types[$call->var->name] . '::' . $call->name->toString();
        }

        return null;
    }

    /**
     * True means the true branch requires a user. False means the false branch does.
     *
     * @param array<string, ReceiverType> $types
     */
    private function predicate(Expr $expression, array $types): ?bool
    {
        if ($expression instanceof Expr\CallLike && ($expression->isFirstClassCallable() || $expression->getArgs() !== [])) {
            return null;
        }
        if ($expression instanceof Expr\BooleanNot) {
            $predicate = $this->predicate($expression->expr, $types);

            return $predicate === null ? null : !$predicate;
        }
        if ($expression instanceof Expr\BinaryOp\NotIdentical || $expression instanceof Expr\BinaryOp\Identical) {
            $left = $expression->left;
            $right = $expression->right;
            if ($left instanceof Expr\ConstFetch && strtolower($left->name->toString()) === 'null') {
                [$left, $right] = [$right, $left];
            }
            if ($right instanceof Expr\ConstFetch && strtolower($right->name->toString()) === 'null' && $this->isIdentityRead($left, $types)) {
                return $expression instanceof Expr\BinaryOp\NotIdentical;
            }
        }
        if ($this->isIdentityRead($expression, $types)) {
            return true;
        }

        return match ($this->authMethod($expression, $types)) {
            'check' => true,
            'guest' => false,
            default => null,
        };
    }

    /** @param array<string, ReceiverType> $types */
    private function authMethod(Expr $expression, array $types): ?string
    {
        if ($expression instanceof Expr\StaticCall && $expression->class instanceof Name && $expression->name instanceof Identifier
            && strtolower($expression->class->toString()) === 'illuminate\\support\\facades\\auth'
        ) {
            return strtolower($expression->name->toString());
        }
        if ($expression instanceof Expr\MethodCall && $expression->name instanceof Identifier
            && $expression->var instanceof Expr\FuncCall
            && $this->callSymbol($expression->var, $types) === 'auth'
            && !isset($this->callables['auth'])
        ) {
            return strtolower($expression->name->toString());
        }

        return null;
    }

    /** @param array<string, ReceiverType> $types */
    private function isIdentityRead(Expr $expression, array $types): bool
    {
        if (!$expression instanceof Expr\MethodCall || !$expression->name instanceof Identifier
            || strtolower($expression->name->toString()) !== 'user' || $expression->args !== []
            || !$expression->var instanceof Expr\Variable || !is_string($expression->var->name)
        ) {
            return false;
        }

        if (!isset($types[$expression->var->name])) {
            // Without a known class, user() cannot prove that the caller is authenticated.
            return false;
        }

        $class = $types[$expression->var->name];
        if (!is_string($class)) {
            return false;
        }

        // A custom user() method can return a value without checking identity.
        // Accept only the supported request method when no local override exists.
        return $this->body($class . '::user') === null
            && (strtolower($class) === 'illuminate\\http\\request' || $this->isFormRequest($class, []));
    }
}
