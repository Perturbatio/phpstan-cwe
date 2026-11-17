<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/eval', function (Request $request): void {
    eval(request('code_2')); // Report: Direct request input.
    $code = $request->input('code');
    eval($code); // Report: Assigned request input.
});

Route::get('/other', function (): void {
    eval($code); // Report: This closure does not inherit the first closure's assignments.
});

$code = $_GET['outer'];
$callback = function (): void {
    eval($code); // Report: This closure does not capture the outer value.
    $code = 'return 1;';
    $nested = function (): void {
        eval($code); // Report: This nested closure does not capture its parent's value.
    };
};
eval($code); // Report: Closure assignments do not replace the outer value.

$arrow = fn () => eval($code); // Report: Captured values are not followed.

$setCode = fn () => $code = request('arrow');
eval($code); // Report: Arrow assignments do not replace the outer value.
