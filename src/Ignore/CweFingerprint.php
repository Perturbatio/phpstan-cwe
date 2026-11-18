<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Ignore;

final class CweFingerprint
{
    /**
     * Make a stable hash from the rule identity and its finding components.
     * A component must not contain comments, line numbers, token positions, or object identities.
     *
     * @param list<string> $components
     */
    public static function make(int $cwe, array $components): string
    {
        return hash('sha256', implode("\0", [sprintf('phpstanCwe.cwe%d', $cwe), ...$components]));
    }
}
