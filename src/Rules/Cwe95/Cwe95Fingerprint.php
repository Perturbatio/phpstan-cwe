<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe95;

final class Cwe95Fingerprint
{
    /**
     * @param list<string> $sources
     */
    public static function make(string $file, string $scope, string $expression, array $sources): string
    {
        sort($sources);

        return hash('sha256', implode("\0", [
            'phpstanCwe.cwe95',
            $file,
            $scope,
            $expression,
            implode('|', $sources),
        ]));
    }
}
