<?php

// @phpstan-ignore phpstanCwe.cwe78 (safe)
exec('fixed-command');

// @phpstan-ignore phpstanCwe.cwe78 (This command uses fixed local input.)
exec('another-fixed-command');
