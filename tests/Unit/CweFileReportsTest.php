<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\CweFileReports;
use Perturbatio\PhpstanCwe\Ignore\CweIgnoreSet;

covers(CweFileReports::class);

function fileReportsAnnotation(string $file, string $fingerprint, string $reason = 'checked input'): array
{
    return [
        'cwe' => 89,
        'file' => $file,
        'line' => 2,
        'startOffset' => 10,
        'endOffset' => 20,
        'startLine' => 3,
        'endLine' => 3,
        'fingerprint' => $fingerprint,
        'reason' => $reason,
    ];
}

it('collects findings once per file and reports annotations in files without findings', function (): void {
    $fingerprint = str_repeat('a', 64);
    $fileA = __FILE__;
    $fileB = __DIR__ . '/CweReportTest.php';
    $fileC = __DIR__ . '/CweIgnoreTest.php';
    $filesVisited = [];
    $reports = CweFileReports::forFiles(
        89,
        80,
        'the SQL text',
        [$fileA, $fileB, $fileA],
        [
            $fileA => [fileReportsAnnotation($fileA, $fingerprint)],
            $fileC => [fileReportsAnnotation($fileC, $fingerprint)],
        ],
        function (string $file, CweFileReports $reports) use (&$filesVisited, $fingerprint, $fileA, $fileB): void {
            $filesVisited[] = $file;
            if ($file === $fileA) {
                $reports->add($fingerprint, 10, 3, 'Review SQL.', 'high', 80);
                $reports->add($fingerprint, 10, 4, 'Review SQL.', 'high', 80, 'Use bindings.');
            }
            if ($file === $fileB) {
                $reports->add($fingerprint, 10, 5, 'Review SQL.', 'medium', 79);
            }
        },
    );

    expect($filesVisited)->toBe([$fileA, $fileB, $fileC])
        ->and($reports)->toHaveCount(2)
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.cwe89')
        ->and($reports[0]->getFile())->toBe($fileA)
        ->and($reports[0]->getLine())->toBe(4)
        ->and($reports[0]->getMetadata()['probability'])->toBe(80)
        ->and($reports[0]->getMetadata()['fingerprint'])->toBe($fingerprint)
        ->and($reports[0]->getTip())->toBe("Use bindings.\n" . CweIgnoreSet::tip(89, $fingerprint, 'the SQL text'))
        ->and($reports[1]->getIdentifier())->toBe('phpstanCwe.unmatchedAnnotation')
        ->and($reports[1]->getFile())->toBe($fileC);
});

it('matches annotations before filtering findings and reports invalid reasons', function (): void {
    $fingerprint = str_repeat('b', 64);
    $reports = CweFileReports::forFiles(
        89,
        90,
        'the SQL text',
        [__FILE__],
        [__FILE__ => [
            fileReportsAnnotation(__FILE__, $fingerprint),
            fileReportsAnnotation(__FILE__, $fingerprint, 'checked'),
        ]],
        function (string $file, CweFileReports $reports) use ($fingerprint): void {
            $reports->add($fingerprint, 15, 3, 'Review SQL.', 'high', 80);
            $reports->add($fingerprint, 15, 3, 'Review SQL.', 'high', 80);
        },
    );

    expect($reports)->toHaveCount(1)
        ->and($reports[0]->getIdentifier())->toBe('phpstanCwe.ignoreReason');
});

it('does not suppress findings outside an annotation and uses the standard tip', function (): void {
    $fingerprint = str_repeat('c', 64);
    $reports = CweFileReports::forFiles(
        89,
        0,
        'the SQL text',
        [__FILE__],
        [__FILE__ => [fileReportsAnnotation(__FILE__, $fingerprint)]],
        function (string $file, CweFileReports $reports) use ($fingerprint): void {
            $reports->add($fingerprint, 21, 4, 'Review SQL.', 'high', 80);
        },
    );

    expect($reports)->toHaveCount(2)
        ->and($reports[0]->getTip())->toBe(CweIgnoreSet::tip(89, $fingerprint, 'the SQL text'))
        ->and($reports[1]->getIdentifier())->toBe('phpstanCwe.unmatchedAnnotation')
        ->and(CweFileReports::forFiles(89, 0, 'the SQL text', [], [], static function (): void {
        }))->toBe([]);
});
