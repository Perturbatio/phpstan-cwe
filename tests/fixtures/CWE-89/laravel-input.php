<?php

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
    }
}

namespace Illuminate\Foundation\Http {
    class FormRequest extends \Illuminate\Http\Request
    {
    }
}

namespace Illuminate\Database\Query {
    class Builder
    {
        public function whereRaw(mixed $sql, array $bindings = []): static
        {
            return $this;
        }
    }
}

namespace {
    use Illuminate\Database\Query\Builder;
    use Illuminate\Foundation\Http\FormRequest;
    use Illuminate\Http\Request;

    use function request as incoming;

    function request($key = null, $default = null): mixed
    {
        return $key === null ? new Request() : $default;
    }

    function checkLaravelInput(Builder $builder, Request $request, FormRequest $formRequest, ?Request $nullable, \PDO $pdo): void
    {
        $builder->whereRaw('id = ' . request('id')); // Report: Helper input changes SQL.
        $builder->whereRaw('id = ' . incoming('id')); // Report: An alias resolves to the helper.
        $builder->whereRaw('id = ' . request()->input('id')); // Report: Helper method input changes SQL.
        $builder->whereRaw('id = ' . $request->input('id')); // Report: Typed request input changes SQL.
        $builder->whereRaw('id = ' . $request->id); // Report: A request property holds input.
        $builder->whereRaw('id = ' . $request['id']); // Report: A request array item holds input.
        $builder->whereRaw('id = ' . $formRequest->input('id')); // Report: A form request extends Request.
        $builder->whereRaw('id = ' . $nullable?->input('id')); // Report: A nullsafe method reads input.
        $builder->whereRaw('id = ' . $nullable?->id); // Report: A nullsafe property reads input.
        $id = $request->input('id');
        $builder->whereRaw('id = ' . $id); // Report: A local assignment holds request input.
        $builder->whereRaw(sql: 'id = ?', bindings: [$request->input('id')]); // No report: Input is bound.
        $builder->whereRaw('id = ' . htmlspecialchars(request('id'))); // Report: HTML escaping does not protect SQL.
        $pdo->query('SELECT * FROM users WHERE id = ' . request('id')); // Report: Helper input reaches PDO.
        $pdo->prepare('SELECT * FROM users WHERE id = ' . $request->input('id')); // Report: Input is already in SQL text.
        $pdo->query('SELECT * FROM users WHERE id = ' . $request->id); // Report: A request property reaches PDO.
        $pdo->query('SELECT * FROM users WHERE id = ' . $request['id']); // Report: A request array item reaches PDO.
        $pdo->prepare('SELECT * FROM users WHERE id = ?')->execute([$request->input('id')]); // No report: Input is bound.
        $pdo->query('SELECT * FROM users WHERE id = ' . (int) request('id')); // No report: The cast returns a number.
        $pdo->query('SELECT * FROM users WHERE id = ' . (float) $request->input('id')); // No report: The cast returns a number.
        mysqli_query(null, 'SELECT * FROM users WHERE id = ' . incoming('id')); // Report: Helper input reaches mysqli.
        $pdo->query('SELECT * FROM users WHERE id = ' . $nullable?->input('id')); // Report: Nullsafe input reaches PDO.
        $pdo->query('SELECT * FROM users WHERE id = ' . $formRequest->input('id')); // Report: Form request input reaches PDO.
    }
}

namespace App {
    function request(string $key): string
    {
        return 'fixed-id';
    }

    function checkShadowedHelper(\Illuminate\Database\Query\Builder $builder, \PDO $pdo): void
    {
        $builder->whereRaw('id = ' . request('id')); // Report: An unrelated helper has an unknown source.
        $builder->whereRaw('id = ' . \request('id')); // Report: The global helper holds request input.
        $pdo->query('SELECT * FROM users WHERE id = ' . request('id')); // No report: This is not the Laravel helper.
        $pdo->query('SELECT * FROM users WHERE id = ' . \request('id')); // Report: The global helper holds request input.
    }
}
