<?php

declare(strict_types=1);

/**
 * Compare rule reports without the path-dependent fingerprint.
 * Tests for the fingerprint itself check it directly.
 */
trait AnalysesWithoutFingerprints
{
    /**
     * @param list<string> $files
     * @param list<array{0: string, 1: int, 2?: string}> $expectedErrors
     */
    public function analyse(array $files, array $expectedErrors): void
    {
        $actual = [];
        foreach ($this->gatherAnalyserErrors($files) as $error) {
            $actual[] = [
                preg_replace('/ Fingerprint: [a-f0-9]{64}\./', '', $error->getMessage()),
                $error->getLine(),
            ];
        }
        $expected = array_map(static fn (array $error): array => [$error[0], $error[1]], $expectedErrors);
        sort($actual);
        sort($expected);

        $this->assertSame($expected, $actual);
    }
}
