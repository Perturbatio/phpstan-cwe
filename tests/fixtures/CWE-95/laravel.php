<?php

use Illuminate\Http\Request;

function evaluateLaravelInput(Request $request): void
{
    eval(request('code')); // Report: Laravel helper input is passed to eval().
    $code = $request->input('code');
    eval($code); // Report: Laravel request input reaches eval() through a local assignment.
}
