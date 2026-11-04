<?php

declare(strict_types=1);

// IDE declarations only. Do not load this file at runtime.
// This file covers the PHPStan 2.x API used by this package, not the full API.

namespace PHPStan {
    class ShouldNotHappenException extends \Exception
    {
        public function __construct(string $message = 'Internal error.')
        {
        }
    }

    class TrinaryLogic
    {
        public function yes(): bool
        {
        }

        public function no(): bool
        {
        }

        public function maybe(): bool
        {
        }
    }
}

namespace PHPStan\Reflection {
    interface NamespaceAnswerer
    {
        public function getNamespace(): ?string;
    }

    interface ReflectionProvider
    {
        public function resolveFunctionName(
            \PhpParser\Node\Name $nameNode,
            ?NamespaceAnswerer $namespaceAnswerer,
        ): ?string;

        public function getClass(string $className): ClassReflection;
    }

    class ClassReflection
    {
        public function getName(): string
        {
        }
    }

    interface FunctionReflection
    {
        public function getName(): string;
    }
}

namespace PHPStan\Reflection\Php {
    class PhpFunctionFromParserNodeReflection implements \PHPStan\Reflection\FunctionReflection
    {
        public function getName(): string
        {
        }
    }
}

namespace PHPStan\Analyser {
    interface Scope extends \PHPStan\Reflection\NamespaceAnswerer
    {
        public function getFile(): string;

        public function getFunction(): ?\PHPStan\Reflection\Php\PhpFunctionFromParserNodeReflection;

        public function getFunctionName(): ?string;

        public function getClassReflection(): ?\PHPStan\Reflection\ClassReflection;

        public function isInAnonymousFunction(): bool;

        public function getType(\PhpParser\Node\Expr $node): \PHPStan\Type\Type;

        public function resolveName(\PhpParser\Node\Name $name): string;
    }
}

namespace PHPStan\Rules {
    /**
     * @template TNodeType of \PhpParser\Node
     */
    interface Rule
    {
        /** @return class-string<TNodeType> */
        public function getNodeType(): string;

        /**
         * @param TNodeType $node
         * @return list<IdentifierRuleError>
         */
        public function processNode(\PhpParser\Node $node, \PHPStan\Analyser\Scope $scope): array;
    }

    interface RuleError
    {
        public function getMessage(): string;
    }

    interface IdentifierRuleError extends RuleError
    {
        public function getIdentifier(): string;
    }

    interface FileRuleError extends RuleError
    {
        public function getFile(): string;

        public function getFileDescription(): string;
    }

    interface LineRuleError extends RuleError
    {
        public function getLine(): int;
    }

    interface MetadataRuleError extends RuleError
    {
        /** @return mixed[] */
        public function getMetadata(): array;
    }

    interface TipRuleError extends RuleError
    {
        public function getTip(): string;
    }

    /** @template-covariant T of RuleError */
    class RuleErrorBuilder
    {
        /** @return self<RuleError> */
        public static function message(string $message): self
        {
        }

        /** @return self<T&IdentifierRuleError> */
        public function identifier(string $identifier): self
        {
        }

        /** @return self<T&MetadataRuleError> */
        public function metadata(array $metadata): self
        {
        }

        /** @return self<T&FileRuleError> */
        public function file(string $file, ?string $fileDescription = null): self
        {
        }

        /** @return self<T&LineRuleError> */
        public function line(int $line): self
        {
        }

        /** @return self<T&TipRuleError> */
        public function tip(string $tip): self
        {
        }

        /** @return T */
        public function build(): RuleError
        {
        }
    }
}

namespace PHPStan\Collectors {
    /**
     * @template-covariant TNodeType of \PhpParser\Node
     * @template-covariant TValue
     */
    interface Collector
    {
        /** @return class-string<TNodeType> */
        public function getNodeType(): string;

        /**
         * @param TNodeType $node
         * @return TValue|null
         */
        public function processNode(\PhpParser\Node $node, \PHPStan\Analyser\Scope $scope);
    }
}

namespace PHPStan\Node {
    interface VirtualNode extends \PhpParser\Node
    {
    }

    class CollectedDataNodeReads
    {
    }

    class CollectedDataNode extends \PhpParser\NodeAbstract implements VirtualNode
    {
        public function __construct(array $collectedData, bool $onlyFiles, ?CollectedDataNodeReads $reads = null)
        {
        }

        /**
         * @template TCollector of \PHPStan\Collectors\Collector<\PhpParser\Node, TValue>
         * @template TValue
         * @param class-string<TCollector> $collectorType
         * @return array<string, list<TValue>>
         */
        public function get(string $collectorType): array
        {
        }

        public function isOnlyFilesAnalysis(): bool
        {
        }

        public function getType(): string
        {
        }

        public function getSubNodeNames(): array
        {
        }
    }

    class FileNode extends \PhpParser\NodeAbstract implements VirtualNode
    {
        /** @param \PhpParser\Node[] $nodes */
        public function __construct(array $nodes)
        {
        }

        /** @return \PhpParser\Node[] */
        public function getNodes(): array
        {
        }

        public function getType(): string
        {
        }

        public function getSubNodeNames(): array
        {
        }
    }
}

namespace PHPStan\Type {
    interface Type
    {
        public function isString(): \PHPStan\TrinaryLogic;

        public function isSuperTypeOf(Type $type): IsSuperTypeOfResult;
    }

    class IsSuperTypeOfResult
    {
        public function yes(): bool
        {
        }

        public function no(): bool
        {
        }

        public function maybe(): bool
        {
        }
    }

    class ObjectType implements Type
    {
        public function __construct(
            string $className,
            ?Type $subtractedType = null,
            ?\PHPStan\Reflection\ClassReflection $classReflection = null,
        ) {
        }

        public function isString(): \PHPStan\TrinaryLogic
        {
        }

        public function isSuperTypeOf(Type $type): IsSuperTypeOfResult
        {
        }
    }

    class MixedType implements Type
    {
        public function __construct(bool $isExplicitMixed = false, ?Type $subtractedType = null)
        {
        }

        public function isString(): \PHPStan\TrinaryLogic
        {
        }

        public function isSuperTypeOf(Type $type): IsSuperTypeOfResult
        {
        }
    }

    class NullType implements Type
    {
        public function __construct()
        {
        }

        public function isString(): \PHPStan\TrinaryLogic
        {
        }

        public function isSuperTypeOf(Type $type): IsSuperTypeOfResult
        {
        }
    }

    class StringType implements Type
    {
        public function __construct()
        {
        }

        public function isString(): \PHPStan\TrinaryLogic
        {
        }

        public function isSuperTypeOf(Type $type): IsSuperTypeOfResult
        {
        }
    }

    class UnionType implements Type
    {
        /** @param list<Type> $types */
        public function __construct(array $types, bool $normalized = false)
        {
        }

        public function isString(): \PHPStan\TrinaryLogic
        {
        }

        public function isSuperTypeOf(Type $otherType): IsSuperTypeOfResult
        {
        }
    }

    class TypeCombinator
    {
        public static function removeNull(Type $type): Type
        {
        }
    }
}

namespace PHPStan\DependencyInjection {
    interface Container
    {
        /**
         * @template T of object
         * @param class-string<T> $className
         * @return T
         */
        public function getByType(string $className);
    }
}

namespace PHPStan\Testing {
    abstract class PHPStanTestCase extends \PHPUnit\Framework\TestCase
    {
        public static function getContainer(): \PHPStan\DependencyInjection\Container
        {
        }

        /** @return list<string> */
        public static function getAdditionalConfigFiles(): array
        {
        }
    }

    /** @template TRule of \PHPStan\Rules\Rule */
    abstract class RuleTestCase extends PHPStanTestCase
    {
        /** @return TRule */
        abstract protected function getRule(): \PHPStan\Rules\Rule;

        /** @return list<\PHPStan\Collectors\Collector> */
        protected function getCollectors(): array
        {
        }

        /**
         * @param list<string> $files
         * @param list<array{0: string, 1: int, 2?: string}> $expectedErrors
         */
        public function analyse(array $files, array $expectedErrors): void
        {
        }
    }
}
