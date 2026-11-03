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
            return 'fixed-text';
        }
    }

    function renderLaravelInput(Request $request, FormRequest $formRequest, OtherRequest $other, ?Request $nullableRequest): void
    {
        echo request('name'); // Report: Helper input reaches HTML.
        print request(key: 'name'); // Report: Named helper input reaches HTML.
        echo request()->input('name'); // Report: The helper returns a request object.
        echo $request->input('name'); // Report: Typed request input reaches HTML.
        echo $request->name; // Report: A request property holds input.
        echo $request['name']; // Report: A request array item holds input.
        echo $formRequest->input('name'); // Report: A form request extends Request.
        echo $nullableRequest?->input('name'); // Report: A nullsafe method reads input.
        echo $nullableRequest?->name; // Report: A nullsafe property reads input.
        echo incoming('name'); // Report: An alias resolves to the global helper.
        echo '<p>', $request->input('name'), '</p>'; // Report: A later echo expression holds input.
        echo htmlspecialchars($request->input('name')); // No report: The input is escaped for HTML.
        print htmlentities(request('name')); // No report: The helper input is escaped for HTML.
        echo (int) $request->input('number'); // No report: The cast returns a number.
        echo (float) request('number'); // No report: The cast returns a number.
        echo htmlspecialchars(request('name')) . $request->name; // Report: The second value is not escaped.
        echo implode(', ', [$request->input('name')]); // Report: Nested input reaches HTML.
        echo $other->input('name'); // No report: The receiver is not a Laravel request.
        echo $request->method(); // No report: This is not a supported input method.
        echo 'fixed-text'; // No report: There is no request input.
        $name = $request->input('name');
        echo $name; // No report: The rule does not follow local assignments.
        echo escapeshellarg(request('name')); // Report: Shell escaping does not protect HTML.
    }
}

namespace App {
    function request(string $key): string
    {
        return 'fixed-text';
    }

    echo request('name'); // No report: This is a different helper.
    echo \request('name'); // Report: The global helper holds request input.
    echo \htmlspecialchars(\request('name')); // No report: The global escape function protects input.
}
