<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Ignore;

use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Trait_;
use PhpParser\NodeFinder;
use PHPStan\Parser\Parser;

final class CweIgnoreParser implements Parser
{
    public function __construct(private readonly Parser $parser)
    {
    }

    public function parseFile(string $file): array
    {
        return $this->filterNativeIgnores($this->parser->parseFile($file));
    }

    public function parseString(string $sourceCode): array
    {
        return $this->filterNativeIgnores($this->parser->parseString($sourceCode));
    }

    /**
     * @param Stmt[] $nodes
     * @return Stmt[]
     */
    private function filterNativeIgnores(array $nodes): array
    {
        if ($nodes === []) {
            return $nodes;
        }

        // PHPStan also stores a copy of the native ignores on each trait.
        foreach ([$nodes[0], ...(new NodeFinder())->findInstanceOf($nodes, Trait_::class)] as $node) {
            /** @var array<int, list<string|array{name: string, comment: string|null}>|null> $lines */
            $lines = $node->getAttribute('linesToIgnore', []);
            if ($lines === []) {
                continue;
            }

            foreach ($lines as $line => $ignores) {
                if ($ignores === null) {
                    continue;
                }

                $remaining = array_values(array_filter(
                    $ignores,
                    static fn (string|array $ignore): bool => preg_match(
                        '/\AphpstanCwe\.cwe(?:78|79|89|95|306)\.[a-z0-9.]+\z/i',
                        is_string($ignore) ? $ignore : $ignore['name'],
                    ) !== 1,
                ));
                if ($remaining === []) {
                    unset($lines[$line]);
                } else {
                    $lines[$line] = $remaining;
                }
            }
            $node->setAttribute('linesToIgnore', $lines);
        }

        return $nodes;
    }
}
