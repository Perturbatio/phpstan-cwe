<?php

declare(strict_types=1);

namespace Perturbatio\PhpstanCwe\Ignore;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\CloningVisitor;
use PhpParser\NodeVisitorAbstract;
use PhpParser\PrettyPrinter\Standard;

final class ExpressionText
{
    /** Print an expression without comments, so that a comment change does not change a fingerprint. */
    public static function of(Node\Expr $expression): string
    {
        $traverser = new NodeTraverser(
            new CloningVisitor(),
            new class () extends NodeVisitorAbstract {
                public function enterNode(Node $node): null
                {
                    $node->setAttribute('comments', []);

                    return null;
                }
            },
        );
        /** @var Node\Expr $clone */
        $clone = $traverser->traverse([$expression])[0];

        return (new Standard())->prettyPrintExpr($clone);
    }
}
