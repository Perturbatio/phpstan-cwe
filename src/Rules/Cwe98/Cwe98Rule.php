<?php

//namespace Perturbatio\PhpstanCwe\Rules\Cwe98;
//
//use PhpParser\Node;
//use PHPStan\Analyser\Scope;
//use PHPStan\Rules\Rule;
//use PHPStan\Rules\RuleErrorBuilder;
//
//final class Cwe98Rule implements Rule
//{
//
//    public function getNodeType(): string
//    {
//        return \PHPStan\Node\CollectedDataNode::class;
//    }
//
//    public function processNode(Node $node, Scope $scope): array
//    {
//        $cwe98Events = $node->get(Cwe98Collector::class, []);
//        $reports = [];
//
//        foreach ($cwe98Events as $event) {
//            if (!isset($event['file'], $event['line'], $event['expression'])) {
//                continue;
//            }
//
//            $reports[] = RuleErrorBuilder::message(
//                sprintf(
//                    'Potential CWE-98: Improper Control of Filename or Path. File: %s, Line: %d, Expression: %s',
//                    $event['file'],
//                    $event['line'],
//                    $event['expression']
//                )
//            )->build();
//        }
//
//        return $reports;
//    }
//}