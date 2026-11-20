<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe;

use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use PHPStan\Rules\IdentifierRuleError;

/** @phpstan-import-type CweIgnoreEvent from CweIgnoreCollector */
final class CweFileReports
{
    private readonly CweIgnoreSet $ignoreSet;

    /** @var list<IdentifierRuleError> */
    private array $reports = [];

    /** @param list<CweIgnoreEvent> $ignores */
    private function __construct(
        private readonly int $cwe,
        private readonly string $file,
        private readonly int $minProbability,
        private readonly string $subject,
        array $ignores,
    ) {
        $this->ignoreSet = new CweIgnoreSet($cwe, $file, $ignores);
    }

    /**
     * @param list<string> $files
     * @param array<string, list<CweIgnoreEvent>> $ignoresByFile
     * @param callable(string, self): void $collect
     * @return list<IdentifierRuleError>
     */
    public static function forFiles(
        int $cwe,
        int $minProbability,
        string $subject,
        array $files,
        array $ignoresByFile,
        callable $collect,
    ): array {
        $reports = [];
        foreach (array_unique([...$files, ...array_keys($ignoresByFile)]) as $file) {
            $file = (string) $file;
            $fileReports = new self($cwe, $file, $minProbability, $subject, $ignoresByFile[$file] ?? []);
            $collect($file, $fileReports);
            array_push($reports, ...$fileReports->reports, ...$fileReports->ignoreSet->reports());
        }

        return $reports;
    }

    public function add(
        string $fingerprint,
        int $offset,
        int $line,
        string $reason,
        string $severity,
        int $probability,
        ?string $extraTip = null,
    ): void {
        // Match the annotation before the probability filter to prevent a false stale report.
        if ($this->ignoreSet->suppressesAt($fingerprint, $offset)
            || !CweReport::isEnabled($this->minProbability, $probability)
        ) {
            return;
        }

        $ignoreTip = CweIgnoreSet::tip($this->cwe, $fingerprint, $this->subject);
        $this->reports[] = CweReport::make(
            $this->cwe,
            $reason,
            $severity,
            $probability,
            $this->file,
            $line,
            tip: $extraTip === null ? $ignoreTip : $extraTip . "\n" . $ignoreTip,
            fingerprint: $fingerprint,
        );
    }
}
