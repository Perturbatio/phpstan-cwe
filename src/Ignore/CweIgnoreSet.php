<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Ignore;

use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\RuleErrorBuilder;

/**
 * Match package ignore annotations with findings in one file. An annotation suppresses
 * one finding only when its hash and reason are valid.
 *
 * @phpstan-import-type CweIgnoreEvent from CweIgnoreCollector
 */
final class CweIgnoreSet
{
    /** @var list<int> */
    private array $matched = [];

    /** @param list<CweIgnoreEvent> $ignores */
    public function __construct(
        private readonly int $cwe,
        private readonly string $file,
        private readonly array $ignores,
    ) {
    }

    public static function tip(int $cwe, string $fingerprint, string $subject): string
    {
        return sprintf(
            'Only ignore this finding if you have checked that %s is safe. Give a reason with at least two words: // @phpstan-ignore phpstanCwe.cwe%d.%s (<reason>)',
            $subject,
            $cwe,
            $fingerprint,
        );
    }

    /** Check an annotation by the token position of the finding. */
    public function suppressesAt(string $fingerprint, int $offset): bool
    {
        return $this->consume(
            $fingerprint,
            static fn (array $ignore): bool => $offset >= $ignore['startOffset'] && $offset <= $ignore['endOffset'],
        );
    }

    /** Check an annotation by the line range of the finding. */
    public function suppressesLines(string $fingerprint, int $startLine, int $endLine): bool
    {
        return $this->consume(
            $fingerprint,
            static fn (array $ignore): bool => $startLine >= $ignore['startLine'] && $endLine <= $ignore['endLine'],
        );
    }

    /**
     * Report malformed annotations and ones that match no finding.
     * Call this method after all findings were checked, including filtered findings.
     *
     * @return list<IdentifierRuleError>
     */
    public function reports(): array
    {
        $reports = [];
        foreach ($this->ignores as $index => $ignore) {
            $hasValidFingerprint = self::isValidFingerprint($ignore['fingerprint']);
            if (!$hasValidFingerprint) {
                $reports[] = $this->report(
                    sprintf('CWE-%d ignore annotation must include a 64-character fingerprint.', $this->cwe),
                    'phpstanCwe.ignoreFingerprint',
                    $ignore['line'],
                );
            }
            if (!self::hasValidReason($ignore['reason'])) {
                $reports[] = $this->report(
                    sprintf('CWE-%d ignore annotation requires a reason with at least two words.', $this->cwe),
                    'phpstanCwe.ignoreReason',
                    $ignore['line'],
                );
            }
            if ($hasValidFingerprint && !in_array($index, $this->matched, true)) {
                $reports[] = $this->report(
                    sprintf('CWE-%d ignore annotation fingerprint does not match a finding. Review or remove this annotation.', $this->cwe),
                    'phpstanCwe.ignoreUnmatched',
                    $ignore['line'],
                );
            }
        }

        return $reports;
    }

    public static function isValidFingerprint(string $fingerprint): bool
    {
        return preg_match('/^[a-f0-9]{64}$/', $fingerprint) === 1;
    }

    public static function hasValidReason(string $reason): bool
    {
        preg_match_all('/[\p{L}\p{N}]+/u', $reason, $matches);

        return count($matches[0]) >= 2;
    }

    /** @param callable(CweIgnoreEvent): bool $contains */
    private function consume(string $fingerprint, callable $contains): bool
    {
        $invalidIndex = null;
        foreach ($this->ignores as $index => $ignore) {
            if (in_array($index, $this->matched, true) || $ignore['fingerprint'] !== $fingerprint || !$contains($ignore)) {
                continue;
            }

            if (self::isValidFingerprint($ignore['fingerprint']) && self::hasValidReason($ignore['reason'])) {
                $this->matched[] = $index;

                return true;
            }
            $invalidIndex ??= $index;
        }

        if ($invalidIndex !== null) {
            $this->matched[] = $invalidIndex;
        }

        return false;
    }

    private function report(string $message, string $identifier, int $line): IdentifierRuleError
    {
        return RuleErrorBuilder::message($message)
            ->identifier($identifier)
            ->file($this->file)
            ->line($line)
            ->build();
    }
}
