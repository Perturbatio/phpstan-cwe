<?php

declare(strict_types=1);

// PHPStan discovers this helper without adding its body to the analysed routes.
function app(?string $abstract = null, array $parameters = []): mixed
{
    return null;
}
