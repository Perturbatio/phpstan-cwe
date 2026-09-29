<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\RuleErrorBuilder;

final class CweReport
{
    public static function isEnabled(int $minimumProbability, int $probability): bool
    {
        if ($minimumProbability < 0 || $minimumProbability > 100) {
            throw new \InvalidArgumentException('phpstanCwe.minProbability must be from 0 to 100.');
        }

        return $probability >= $minimumProbability;
    }

    public static function make(
        int $cwe,
        string $reason,
        string $severity,
        int $probability,
        ?string $file = null,
        ?int $line = null,
    ): IdentifierRuleError {
        $url = sprintf('https://cwe.mitre.org/data/definitions/%d.html', $cwe);

        $builder = RuleErrorBuilder::message(sprintf(
            'CWE-%d: %s Severity: %s. Probability: %d%%. %s',
            $cwe,
            $reason,
            $severity,
            $probability,
            $url,
        ))
            ->identifier(sprintf('phpstanCwe.cwe%d', $cwe))
            ->metadata(['cwe' => $cwe, 'severity' => $severity, 'probability' => $probability, 'url' => $url]);
        if ($file !== null) {
            $builder->file($file);
        }
        if ($line !== null) {
            $builder->line($line);
        }

        return $builder->build();
    }
}
