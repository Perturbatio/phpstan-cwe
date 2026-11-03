<?php

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;

beforeEach(function (): void {
    $parser = (new ParserFactory())->createForNewestSupportedVersion();
    $nodes = $parser->parse(file_get_contents(__DIR__ . '/../../stubs/phpstan.php'));
    $nodes = (new NodeTraverser(new NameResolver()))->traverse($nodes);
    $this->stubDeclarations = (new NodeFinder())->findInstanceOf($nodes, Node\Stmt\ClassLike::class);
});

it('declares installed PHPStan types without loading the IDE file', function (): void {
    expect($this->stubDeclarations)->not->toBeEmpty();

    foreach ($this->stubDeclarations as $declaration) {
        $reflection = new ReflectionClass($declaration->namespacedName->toString());

        expect($reflection->isInterface())->toBe($declaration instanceof Node\Stmt\Interface_)
            ->and(str_contains($reflection->getFileName(), '/stubs/'))->toBeFalse();

        $parents = $declaration instanceof Node\Stmt\Interface_
            ? $declaration->extends
            : array_filter([$declaration->extends, ...$declaration->implements]);

        foreach ($parents as $parent) {
            expect($reflection->isSubclassOf($parent->toString()))->toBeTrue();
        }
    }
});

it('keeps IDE method signatures consistent with the installed PHPStan API', function (): void {
    $printer = new Standard();

    foreach ($this->stubDeclarations as $declaration) {
        $className = $declaration->namespacedName->toString();

        foreach ($declaration->getMethods() as $method) {
            $reflection = new ReflectionMethod($className, $method->name->toString());
            $parameters = $reflection->getParameters();

            expect($method->isStatic())->toBe($reflection->isStatic())
                ->and($method->isPublic())->toBe($reflection->isPublic())
                ->and($method->params)->toHaveCount(count($parameters));

            $normalizeType = static fn (string $type): string => str_replace(
                '\\',
                '',
                $type === 'self' ? $className : $type,
            );
            $returnType = $method->returnType === null ? '' : $printer->prettyPrint([$method->returnType]);

            expect($normalizeType($returnType))->toBe($normalizeType((string) $reflection->getReturnType()));

            foreach ($method->params as $index => $parameter) {
                $type = $parameter->type === null ? '' : $printer->prettyPrint([$parameter->type]);

                expect($parameter->var->name)->toBe($parameters[$index]->getName())
                    ->and($normalizeType($type))->toBe($normalizeType((string) $parameters[$index]->getType()))
                    ->and($parameter->default !== null)->toBe($parameters[$index]->isDefaultValueAvailable());
            }
        }
    }
});
