<?php

namespace Illuminate\Database\Query {
    trait RawQueryMethods
    {
        public function whereRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function orWhereRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function havingRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function orHavingRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function orderByRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function groupByRaw(mixed $sql, mixed $bindings = []): static
        {
            return $this;
        }

        public function selectRaw(mixed $expression, mixed $bindings = []): static
        {
            return $this;
        }

        public function fromRaw(mixed $expression, mixed $bindings = []): static
        {
            return $this;
        }

        public function where(mixed $column, mixed $value): static
        {
            return $this;
        }
    }

    class Builder
    {
        use RawQueryMethods;
    }
}

namespace Illuminate\Database\Eloquent {
    class Builder
    {
        use \Illuminate\Database\Query\RawQueryMethods;
    }
}

namespace Illuminate\Database\Eloquent\Relations {
    class Relation
    {
        use \Illuminate\Database\Query\RawQueryMethods;
    }
}

namespace Illuminate\Support\Facades {
    class DB
    {
        public static function select(string $query, array $bindings = []): array
        {
            return [];
        }

        public static function insert(string $query, array $bindings = []): bool
        {
            return true;
        }

        public static function update(string $query, array $bindings = []): int
        {
            return 0;
        }

        public static function delete(string $query, array $bindings = []): int
        {
            return 0;
        }
    }
}

namespace {
    use Illuminate\Support\Facades\DB;

    class OtherBuilder
    {
        public function whereRaw(mixed $sql): void
        {
        }
    }

    function getUnknownValue(): string
    {
        return 'unknown';
    }

    function checkLaravelQueries(string $unknownParameter): void
    {
        $queryBuilder = new \Illuminate\Database\Query\Builder();
        $eloquentBuilder = new \Illuminate\Database\Eloquent\Builder();
        $relation = new \Illuminate\Database\Eloquent\Relations\Relation();
        $otherBuilder = new OtherBuilder();
        $unknownValue = $_SESSION['value'];

        $queryBuilder->whereRaw("id = '" . $_GET['id']); // Report: GET input changes raw SQL.
        $queryBuilder->orWhereRaw("id = '" . $_POST['id']); // Report: POST input changes raw SQL.
        $queryBuilder->havingRaw("name = '" . $_COOKIE['name']); // Report: COOKIE input changes raw SQL.
        $queryBuilder->orHavingRaw("name = '" . $_REQUEST['name']); // Report: REQUEST input changes raw SQL.
        $queryBuilder->orderByRaw('FIELD(id, ' . $_GET['id']); // Report: GET input changes raw SQL.
        $queryBuilder->groupByRaw('FIELD(id, ' . $_POST['id']); // Report: POST input changes raw SQL.
        $queryBuilder->selectRaw('price * ' . $_COOKIE['price']); // Report: COOKIE input changes raw SQL.
        $queryBuilder->fromRaw('users_' . $_REQUEST['table']); // Report: REQUEST input changes raw SQL.
        $queryBuilder->whereRaw(sql: 'id = ' . $_GET['id']); // Report: Named raw SQL argument has GET input.
        $queryBuilder->whereRaw(sql: 'id = ?', bindings: [$_GET['id']]); // No report: GET input is a bound value.
        $queryBuilder->where('id', $_GET['id']); // No report: The builder binds this value.
        $eloquentBuilder->whereRaw('id = ' . $_GET['id']); // Report: Eloquent raw SQL has GET input.
        $relation->whereRaw('id = ' . $_GET['id']); // Report: Relation raw SQL has GET input.
        $otherBuilder->whereRaw('id = ' . $_GET['id']); // No report: This is not a Laravel builder.
        $queryBuilder->whereRaw('id = ' . $unknownValue); // Report: The value source is unknown.
        $queryBuilder->whereRaw('id = ' . getenv('QUERY_PART')); // Report: The environment value has unknown safety.
        $queryBuilder->whereRaw('id = 123'); // No report: The SQL expression is static.
        $queryBuilder->whereRaw('id = ' . '123'); // No report: Both concatenated parts are static.

        $user = $_GET['username'];
        $password = $_GET['password'];
        DB::select("SELECT * FROM users WHERE username = '$user' AND password = '$password'"); // Report: Local variables contain request data.
        DB::select('SELECT * FROM users WHERE username = ? AND password = ?', [$_GET['username'], $_GET['password']]); // No report: Values are bound.
        DB::insert("INSERT INTO users (username) VALUES ('$user')"); // Report: INSERT SQL has request data.
        DB::insert('INSERT INTO users (username) VALUES (?)', [$user]); // No report: The value is bound.
        DB::update("UPDATE users SET password = '$password' WHERE username = '$user'"); // Report: UPDATE SQL has request data.
        DB::update('UPDATE users SET password = ? WHERE username = ?', [$password, $user]); // No report: Values are bound.
        DB::delete("DELETE FROM users WHERE username = '$user'"); // Report: DELETE SQL has request data.
        DB::delete('DELETE FROM users WHERE username = ?', [$user]); // No report: The value is bound.

        $valueFromUnknownSource = getUnknownValue();
        DB::select('SELECT * FROM users WHERE name = ' . $valueFromUnknownSource); // Report: The local value source is unknown.
        DB::select('SELECT * FROM users WHERE name = ' . $unknownParameter); // Report: The parameter source is unknown.
    }
}
