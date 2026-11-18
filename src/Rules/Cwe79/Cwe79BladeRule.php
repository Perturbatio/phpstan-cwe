<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe79;

use Perturbatio\PhpstanCwe\Blade\AnalysedFileCollector;
use Perturbatio\PhpstanCwe\Blade\BladeTemplateScanner;
use Perturbatio\PhpstanCwe\CweReport;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;
use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\Rule;

/** @implements Rule<CollectedDataNode> */
final class Cwe79BladeRule implements Rule
{
    private const string SEVERITY = 'high';

    /** @param list<string> $directories */
    public function __construct(
        private readonly BladeTemplateScanner $scanner,
        private readonly array $directories,
        private readonly int $minProbability = 0,
    ) {
        // Check the minimum score when PHPStan creates this rule.
        CweReport::isEnabled($minProbability, self::getProbability());
    }

    public static function getProbability(): int
    {
        return 80;
    }

    public static function getIgnoreTip(string $fingerprint): string
    {
        return 'Only if you are sure that this value is safe HTML, put '
            . sprintf('{{-- @phpstan-ignore phpstanCwe.cwe79.%s (<reason>) --}} ', $fingerprint)
            . 'immediately BEFORE this raw echo. Give a reason with at least two words.';
    }

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        // Skip scans when PHPStan found no Blade files or the rule is disabled
        if ($node->get(AnalysedFileCollector::class) === []
            || !CweReport::isEnabled($this->minProbability, self::getProbability())
        ) {
            return [];
        }

        // Report the template location, not the PHP file that starts the scan
        $errors = [];
        $findings = $this->scanner->scan($this->directories);
        $ignoresByFile = [];
        foreach ($findings as $finding) {
            if ($finding['type'] === 'packageIgnore') {
                $ignoresByFile[$finding['file']][] = $finding['ignore'];
            }
        }
        $ignoreSets = [];
        foreach ($ignoresByFile as $file => $ignores) {
            $ignoreSets[$file] = new CweIgnoreSet(79, $file, $ignores);
        }

        foreach (array_filter($findings, static fn (array $finding): bool => $finding['type'] === 'rawEcho') as $finding) {
            if (($ignoreSets[$finding['file']] ?? null)?->suppressesAt($finding['fingerprint'], $finding['offset']) === true) {
                continue;
            }
            // A Blade raw echo skips the normal HTML escaping
            $errors[] = CweReport::make(
                79,
                'A Blade raw echo prints a value without HTML escape.',
                self::SEVERITY,
                self::getProbability(),
                $finding['file'],
                $finding['line'],
                self::getIgnoreTip($finding['fingerprint']),
                $finding['fingerprint'],
            );
        }
        foreach ($ignoreSets as $ignoreSet) {
            $errors = array_merge($errors, $ignoreSet->reports());
        }

        return $errors;
    }
}
