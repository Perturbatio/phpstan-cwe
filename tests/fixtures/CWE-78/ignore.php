<?php

// @phpstan-ignore phpstanCwe.cwe78.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (safe)
exec('fixed-command');

// @phpstan-ignore phpstanCwe.cwe78.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (This command uses fixed local input.)
exec('another-fixed-command');
