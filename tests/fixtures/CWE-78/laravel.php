<?php

declare(strict_types=1);

namespace Illuminate\Http {
    class Request extends \ArrayObject
    {
        public function input($key = null, $default = null): mixed
        {
            return $default;
        }

        public function __get(string $key): mixed
        {
            return null;
        }

        public function method(): string
        {
            return 'GET';
        }
    }
}

namespace Illuminate\Foundation\Http {
    class FormRequest extends \Illuminate\Http\Request
    {
    }
}

namespace {
    use Illuminate\Http\Request;
    use Illuminate\Foundation\Http\FormRequest;

    use function request as incoming;

    function request($key = null, $default = null): mixed
    {
        return $key === null ? new Request() : $default;
    }

    class OtherRequest
    {
        public function input(string $key): string
        {
            return 'fixed-command';
        }
    }

    function runLaravelCommands(Request $request, FormRequest $formRequest, OtherRequest $other): void
    {
        exec(request('command')); // Report: Helper input is the full command.
        exec('tool ' . request(key: 'file')); // Report: Helper input changes an argument.
        exec(request()->input('command')); // Report: The helper returns a request object.
        exec($request->input('command')); // Report: Typed request input is the full command.
        exec($request->command); // Report: A request property holds input.
        exec($request['command']); // Report: A request array item holds input.
        exec($formRequest->input('command')); // Report: A form request extends Request.
        $command = $request->input('command');
        exec($command); // Report: A local assignment holds request input.
        exec('tool ' . escapeshellarg($request->input('file'))); // Report: Protected arguments still get a low review score.
        exec($other->input('command')); // Report: An unrelated receiver gets only a low review score.
        exec($request->method()); // Report: A non-input method gets only a low review score.
        exec(incoming('command')); // Report: An alias resolves to the global helper.
        $command = 'tool fixed-file';
        exec($command); // Report: Reassignment removes the request source.
        $process = proc_open(['tool', request('file')], [], $pipes); // Report: Only the executable is checked.
        $process = proc_open([request('command'), 'file'], [], $pipes); // Report: The executable holds request input.
        $output = shell_exec('tool ' . $request->command); // Report: Shell execution uses request input.
        // @phpstan-ignore phpstanCwe.cwe78 (The application checks this command against a fixed allowlist.)
        exec(request('reviewed-command')); // No report: The inline ignore has a clear reason.
    }

    function runNullableRequest(?Request $request): void
    {
        exec($request?->input('command')); // Report: Nullsafe method input is the full command.
        exec($request?->command); // Report: Nullsafe property input is the full command.
    }
}

namespace App {
    function request(string $key): string
    {
        return 'fixed-command';
    }

    exec(request('command')); // Report: A shadowed helper gets only a low review score.
    exec(\request('command')); // Report: The qualified global helper holds request input.
}
