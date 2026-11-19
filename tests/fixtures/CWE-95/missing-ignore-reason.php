<?php

function evaluateWithoutIgnoreReason(): void
{
    /* @phpstan-ignore phpstanCwe.cwe95.0000000000000000000000000000000000000000000000000000000000000000 */
    eval($_GET['code']); // Report: The annotation has no reason and does not suppress this finding.
}
