<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Blade;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

final class BladeTemplateScanner
{
    /**
     * @param list<string> $directories
     * @return list<array{file: string, line: int}>
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
            foreach ($files as $file) {
                if ($file instanceof SplFileInfo && $file->isFile() && str_ends_with($file->getFilename(), '.blade.php')) {
                    $realPath = $file->getRealPath();
                    if ($realPath === false) {
                        throw new \RuntimeException(sprintf('Cannot resolve Blade view: %s', $file->getPathname()));
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

    /** @return list<array{file: string, line: int}> */
    private function scanFile(string $file): array
    {
        $source = file_get_contents($file);
        if ($source === false) {
            throw new \RuntimeException(sprintf('Cannot read Blade view: %s', $file));
        }

        // Keep newlines when Blade comments and verbatim blocks are hidden.
        $masked = preg_replace_callback(
            '/\{\{--.*?--\}\}|@verbatim\b.*?@endverbatim\b/s',
            static function (array $match): string {
                $blank = preg_replace('/[^\r\n]/', ' ', $match[0]);
                if ($blank === null) {
                    throw new \RuntimeException('Cannot hide a Blade comment or verbatim block.');
                }

                return $blank;
            },
            $source,
        );
        if ($masked === null) {
            throw new \RuntimeException(sprintf('Cannot scan Blade view: %s', $file));
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
            $findings[] = ['file' => $file, 'line' => substr_count($source, "\n", 0, $offset) + 1];
        }

        return $findings;
    }
}
