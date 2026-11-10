<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Rules\Cwe306;

final class CriticalOperationMatcher
{
    private const IDENTIFIER = '[a-z_\\x80-\\xff][a-z0-9_\\x80-\\xff]*';

    /** @var array<string, string> */
    private array $exactOperations = [];

    /** @var array<string, string> */
    private array $includedPatterns = [];

    /** @var array<string, string> */
    private array $excludedPatterns = [];

    /** @param list<string> $operations */
    public function __construct(array $operations)
    {
        foreach ($operations as $operation) {
            $excluded = str_starts_with($operation, '!');
            $name = $excluded ? substr($operation, 1) : $operation;
            if (!$this->isValidOperation($name)) {
                throw new \InvalidArgumentException(
                    'CWE-306 critical operations must be function names or Class::method names. Use * within identifiers, ** for complete namespace segments, and ! before exclusion patterns.',
                );
            }

            $normalized = ltrim($name, '\\');
            $key = strtolower($normalized);
            $isPattern = str_contains($normalized, '*');
            if ($isPattern && !str_contains($normalized, '::')) {
                throw new \InvalidArgumentException('CWE-306 wildcard patterns must identify a Class::method operation.');
            }
            if ($excluded && !$isPattern) {
                throw new \InvalidArgumentException('CWE-306 exclusions must use wildcard patterns.');
            }
            if (!$isPattern) {
                $this->exactOperations[$key] = $normalized;
                continue;
            }

            $regex = $this->compilePattern($key);
            if ($excluded) {
                $this->excludedPatterns[$regex] = $regex;

                continue;
            }
            $this->includedPatterns[$regex] = $regex;
        }
    }

    public function hasCriticalOperations(): bool
    {
        return $this->exactOperations !== [] || $this->includedPatterns !== [];
    }

    public function match(string $operation): ?string
    {
        return $this->matchAny([$operation]);
    }

    /** @param non-empty-list<string> $operations */
    public function matchAny(array $operations): ?string
    {
        $normalized = array_map(static fn (string $operation): string => ltrim($operation, '\\'), $operations);
        $keys = array_map('strtolower', $normalized);

        foreach ($this->excludedPatterns as $pattern) {
            foreach ($keys as $key) {
                if (preg_match($pattern, $key) === 1) {
                    return null;
                }
            }
        }

        foreach ($keys as $key) {
            if (isset($this->exactOperations[$key])) {
                return $this->exactOperations[$key];
            }
        }

        foreach ($this->includedPatterns as $pattern) {
            foreach ($keys as $index => $key) {
                if (preg_match($pattern, $key) === 1) {
                    return $normalized[$index];
                }
            }
        }

        return null;
    }

    private function isValidOperation(string $operation): bool
    {
        if (preg_match(
            '/^\\\\?[a-zA-Z_*\x80-\xff][a-zA-Z0-9_*\x80-\xff]*(?:\\\\[a-zA-Z_*\x80-\xff][a-zA-Z0-9_*\x80-\xff]*)*(?:::[a-zA-Z_*\x80-\xff][a-zA-Z0-9_*\x80-\xff]*)?$/D',
            $operation,
        ) !== 1) {
            return false;
        }

        $parts = explode('::', $operation);
        if (isset($parts[1]) && str_contains($parts[1], '**')) {
            return false;
        }
        if (str_contains($parts[0], '**\\**')) {
            return false;
        }
        $classParts = explode('\\', $parts[0]);
        foreach ($classParts as $index => $part) {
            if (str_contains($part, '**')
                && ($part !== '**' || $index === count($classParts) - 1)) {
                return false;
            }
        }

        return true;
    }

    private function compilePattern(string $pattern): string
    {
        $parts = explode('::', $pattern);
        $classParts = explode('\\', $parts[0]);
        $separator = preg_quote('\\', '~');
        // Check the full symbol so a partial wildcard cannot match an invalid identifier.
        $regex = '(?=' . self::IDENTIFIER . '(?:' . $separator . self::IDENTIFIER . ')*::' . self::IDENTIFIER . '\z)';
        foreach ($classParts as $index => $part) {
            if ($part === '**') {
                $regex .= '(?:' . self::IDENTIFIER . $separator . ')*';
            } else {
                $regex .= $this->compileIdentifier($part);
                $regex .= $index === count($classParts) - 1 ? '::' : $separator;
            }
        }
        $regex .= $this->compileIdentifier($parts[1]);

        return '~^' . $regex . '\z~';
    }

    private function compileIdentifier(string $pattern): string
    {
        return str_replace('\*', '[a-z0-9_\x80-\xff]*', preg_quote($pattern, '~'));
    }
}
