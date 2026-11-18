<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Blade;

use Perturbatio\PhpstanCwe\Ignore\CweFingerprint;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreCollector;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * A raw echo has a fingerprint. A package ignore uses the offset of the raw echo that follows it, or -1.
 *
 * @phpstan-type BladeFinding array{file: string, line: int, type: 'rawEcho', offset: int, fingerprint: string}
 *     |array{file: string, line: int, type: 'packageIgnore', ignore: CweIgnoreEvent}
 * @phpstan-import-type CweIgnoreEvent from CweIgnoreCollector
 */
final class BladeTemplateScanner
{
    /**
     * @param list<string> $directories
     * @return list<BladeFinding>
     */
    public function scan(array $directories): array
    {
        $findings = [];
        $workingDirectory = getcwd();
        if ($workingDirectory === false) {
            throw new \RuntimeException('Cannot get the current directory for the Blade scan.');
        }

        $scannedFiles = [];
        foreach ($directories as $directory) {
            $path = str_starts_with($directory, '/') ? $directory : $workingDirectory . '/' . $directory;
            if (!is_dir($path)) {
                // A non-Laravel project does not have the default view directory.
                if ($directory === 'resources/views') {
                    continue;
                }
                throw new \InvalidArgumentException(sprintf('Blade view directory does not exist: %s', $path));
            }

            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
            /** @var SplFileInfo $file */
            foreach ($files as $file) {
                if ($file->isFile() && str_ends_with($file->getFilename(), '.blade.php')) {
                    $realPath = $file->getRealPath();
                    if ($realPath === false) {
                        // The path can become invalid between isFile() and getRealPath().
                        throw new \RuntimeException(sprintf('Cannot resolve Blade view: %s', $file->getPathname())); // @codeCoverageIgnore
                    }
                    if (isset($scannedFiles[$realPath])) {
                        continue;
                    }
                    $scannedFiles[$realPath] = true;
                    $findings = array_merge($findings, $this->scanFile($file->getPathname()));
                }
            }
        }

        return $findings;
    }

    /** @return list<BladeFinding> */
    private function scanFile(string $file): array
    {
        $source = file_get_contents($file);
        if ($source === false) {
            throw new \RuntimeException(sprintf('Cannot read Blade view: %s', $file));
        }

        $hide = $this->hideMatchedText(...);
        $withoutVerbatim = preg_replace_callback('/@verbatim\b.*?@endverbatim\b/s', $hide, $source);
        if ($withoutVerbatim === null) {
            throw new \RuntimeException(sprintf('Cannot scan Blade view: %s', $file));
        }

        if (preg_match_all('/\{\{--(.*?)--\}\}/s', $withoutVerbatim, $comments, PREG_OFFSET_CAPTURE) === false) {
            throw new \RuntimeException(sprintf('Cannot scan Blade comments in view: %s', $file));
        }
        $packageIgnores = [];
        foreach ($comments[0] as $index => [$comment, $offset]) {
            if ($offset !== 0 && $source[$offset - 1] === '@') {
                continue;
            }
            if (preg_match(
                '/\A[ \t]*@phpstan-ignore[ \t]+phpstanCwe\.cwe79(?:\.([a-z0-9.]+))?[ \t]*(?:\(([^)\r\n]*)\))?[ \t]*\z/i',
                $comments[1][$index][0],
                $packageMatch,
            ) === 1) {
                $packageIgnores[$offset + strlen($comment)] = [
                    'line' => substr_count($source, "\n", 0, $offset) + 1,
                    'fingerprint' => strtolower($packageMatch[1] ?? ''),
                    'reason' => trim($packageMatch[2] ?? ''),
                    'offset' => -1,
                ];
            }
        }

        $masked = preg_replace_callback('/\{\{--.*?--\}\}/s', $hide, $withoutVerbatim);
        if ($masked === null) {
            throw new \RuntimeException(sprintf('Cannot hide Blade comments in view: %s', $file)); // @codeCoverageIgnore
        }
        if (preg_match_all('/\{!!(.*?)!!\}/s', $masked, $matches, PREG_OFFSET_CAPTURE) === false) {
            throw new \RuntimeException(sprintf('Cannot scan raw echoes in Blade view: %s', $file));
        }
        $findings = [];
        foreach ($matches[0] as $index => [, $offset]) {
            // Blade prints an escaped @ directive as text.
            if ($offset > 0 && $masked[$offset - 1] === '@') {
                continue;
            }
            $expression = trim($matches[1][$index][0]);
            // A fixed string cannot contain request input.
            if (preg_match('/^(?:\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\$])*")$/s', $expression) === 1) {
                continue;
            }
            foreach ($packageIgnores as $end => $packageIgnore) {
                if ($end <= $offset
                    && preg_match('/\A[ \t]*(?:\r?\n[ \t]*)?\z/', substr($source, $end, $offset - $end)) === 1
                ) {
                    $packageIgnores[$end]['offset'] = $offset;
                }
            }
            $findings[] = [
                'file' => $file,
                'line' => substr_count($source, "\n", 0, $offset) + 1,
                'type' => 'rawEcho',
                'offset' => $offset,
                'fingerprint' => CweFingerprint::make(79, [$file, 'blade', $this->normalise($expression)]),
            ];
        }
        foreach ($packageIgnores as $packageIgnore) {
            $findings[] = [
                'file' => $file,
                'line' => $packageIgnore['line'],
                'type' => 'packageIgnore',
                'ignore' => [
                    'cwe' => 79,
                    'file' => $file,
                    'line' => $packageIgnore['line'],
                    'startOffset' => $packageIgnore['offset'],
                    'endOffset' => $packageIgnore['offset'],
                    'startLine' => $packageIgnore['line'],
                    'endLine' => $packageIgnore['line'],
                    'fingerprint' => $packageIgnore['fingerprint'],
                    'reason' => $packageIgnore['reason'],
                ],
            ];
        }
        return $findings;
    }

    private function normalise(string $expression): string
    {
        // Blank space and newline changes must not change a fingerprint.
        $normalised = preg_replace('/\s+/u', ' ', $expression);

        return $normalised ?? $expression;
    }

    /** @param array<string> $match */
    private function hideMatchedText(array $match): string
    {
        // Keep newlines so the report points to the line in the view.
        $blank = preg_replace('/[^\r\n]/', ' ', $match[0]);
        if ($blank === null) {
            throw new \RuntimeException('Cannot hide a Blade comment or verbatim block.'); // @codeCoverageIgnore
        }

        return $blank;
    }
}
