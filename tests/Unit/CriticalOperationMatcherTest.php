<?php

declare(strict_types=1);

use Perturbatio\PhpstanCwe\Rules\Cwe306\CriticalOperationMatcher;

covers(CriticalOperationMatcher::class);

it('matches wildcard segments without changing exact operation behaviour', function (): void {
    $matcher = new CriticalOperationMatcher([
        'eraseAccounts',
        '\App\Services\AccountService::delete',
        'App\Services\*::delete',
    ]);

    expect($matcher->match('eraseAccounts'))->toBe('eraseAccounts')
        ->and($matcher->match('\APP\Services\AccountService::DELETE'))->toBe('App\Services\AccountService::delete')
        ->and($matcher->match('App\Services\InvoiceService::delete'))->toBe('App\Services\InvoiceService::delete')
        ->and($matcher->match('App\Services\InvoiceService::deleteAll'))->toBeNull()
        ->and($matcher->match('App\Services\Billing\InvoiceService::delete'))->toBeNull()
        ->and($matcher->match('App\ServicesExtra\InvoiceService::delete'))->toBeNull();
});

it('matches methods on direct child action classes', function (): void {
    $matcher = new CriticalOperationMatcher(['App\Actions\Data\DeleteRecords\*::*']);

    expect($matcher->hasCriticalOperations())->toBeTrue()
        ->and($matcher->match('App\Actions\Data\DeleteRecords\OldRecordsAction::handle'))
        ->toBe('App\Actions\Data\DeleteRecords\OldRecordsAction::handle')
        ->and($matcher->match('App\Actions\Data\DeleteRecords\Nested\OldRecordsAction::handle'))
        ->toBeNull();
});

it('lets exclusion patterns override exact names and inclusion patterns regardless of order', function (array $operations): void {
    $matcher = new CriticalOperationMatcher($operations);

    expect($matcher->match('App\Services\Legacy\LegacyService::delete'))->toBeNull()
        ->and($matcher->match('App\Services\AccountService::delete'))->toBe('App\Services\AccountService::delete')
        ->and($matcher->hasCriticalOperations())->toBeTrue();
})->with([
    [
        [
            'App\Services\Legacy\LegacyService::delete',
            'App\Services\*::*',
            '!App\Services\Legacy\*::*',
        ],
    ],
    [
        [
            '!App\Services\Legacy\*::*',
            'App\Services\*::*',
            'App\Services\Legacy\LegacyService::delete',
        ],
    ],
]);

it('lets exclusions match either the runtime or declaring operation', function (): void {
    $matcher = new CriticalOperationMatcher([
        'App\BaseService::delete',
        '!App\LegacyService::*',
    ]);

    expect($matcher->matchAny(['App\LegacyService::delete', 'App\BaseService::delete']))->toBeNull();
});

it('does not treat an exclusion-only list as an enabled operation source', function (): void {
    $matcher = new CriticalOperationMatcher(['!App\Services\Legacy\*::*']);

    expect($matcher->hasCriticalOperations())->toBeFalse()
        ->and($matcher->match('App\Services\Legacy\LegacyService::delete'))->toBeNull();
});

it('keeps empty configuration and global namespace boundaries explicit', function (): void {
    $emptyMatcher = new CriticalOperationMatcher([]);
    $matcher = new CriticalOperationMatcher(['\*::*', 'App\*::delete', '\App\*::delete']);

    expect($emptyMatcher->hasCriticalOperations())->toBeFalse()
        ->and($emptyMatcher->match('AccountService::delete'))->toBeNull()
        ->and($matcher->match('\AccountService::delete'))->toBe('AccountService::delete')
        ->and($matcher->match('\APP\AccountService::DELETE'))->toBe('APP\AccountService::DELETE')
        ->and($matcher->match('Other\AccountService::delete'))->toBeNull()
        ->and($matcher->match('AccountService::delete' . "\n"))->toBeNull()
        ->and($matcher->match('AccountService::delete::extra'))->toBeNull();
});

it('rejects malformed or unsupported operation patterns', function (string $operation): void {
    expect(fn () => new CriticalOperationMatcher([$operation]))
        ->toThrow(InvalidArgumentException::class);
})->with([
    '',
    '!!App\*::*',
    'App\*',
    '*',
    'App\Services\delete*',
    'App\Services\**::delete',
    'App\Services\*::dele?te',
    '!App\Services::delete',
    '!eraseAccounts',
    'App\Services\*::',
    'App\Services\*:::delete',
]);

it('explains invalid operation syntax in the configuration error', function (): void {
    expect(fn () => new CriticalOperationMatcher(['App\Services\delete*']))
        ->toThrow(InvalidArgumentException::class, 'CWE-306 wildcard patterns must identify a Class::method operation.');
});

it('matches symbol globs at identifier and namespace boundaries', function (string $pattern, string $operation, bool $matches): void {
    $matcher = new CriticalOperationMatcher([$pattern]);
    expect($matcher->match($operation))->toBe($matches ? ltrim($operation, '\\') : null);
})->with([
    ['App\Models\**\*::delete', 'App\Models\User::delete', true],
    ['App\Models\**\*::delete', 'App\Models\Admin\Audit\User::delete', true],
    ['App\Models\**\*::delete', 'App\ModelsExtra\User::delete', false],
    ['App\Models\**\*::delete', 'App\Models\User::forceDelete', false],
    ['App\Models\**\*::delete', 'App\Models\User::deleteQuietly', false],
    ['App\Models\**\*::delete', 'App\Models\::delete', false],
    ['App\Models\**\*::delete', 'App\Models\1User::delete', false],
    ['App\Models\**\*::delete', 'App\Models\1Admin\User::delete', false],
    ['App\Models\**\*::delete', 'App\Models\\\User::delete', false],
    ['App\**\*Controller::delete*', 'App\Http\UserController::deleteAccount', true],
    ['App\**\*Controller::delete*', 'App\Controller::delete', true],
    ['App\**\*Controller::delete*', 'App\Service::delete', false],
    ['App\**\*Controller::delete*', 'App\Controller::1delete', false],
    ['App\**\*Controller::delete*', 'App\Controller::delete\extra', false],
    ['App\**\*Controller::delete*', 'App\Controller::delete' . "\n", false],
    ['App\**\*Controller::delete*', 'App\Controller::delete::extra', false],
    ['App\**\Admin\*::delete', 'App\Admin\User::delete', true],
    ['App\**\Admin\*::delete', 'App\Models\Admin\User::delete', true],
    ['App\**\Admin\*::delete', 'App\Models\AdminExtra\User::delete', false],
    ['App\**\Admin\*::delete', 'App\Models\User::delete', false],
    ['**\*::delete', 'User::delete', true],
    ['**\*::delete', 'App\Models\User::delete', true],
    ['App\Mod*ls\Us*r::de*te', 'App\Models\User::delete', true],
    ['App\Mod*ls\Us*r::de*te', 'App\Modls\Usr::dete', true],
    ['App\Mod*ls\Us*r::de*te', 'App\Mod\els\User::delete', false],
    ['App\*A*B*::*', 'App\AB::delete', true],
    ['App\*A*B*::*', 'App\FirstASecondBThird::delete', true],
    ['App\*A*B*::*', 'App\BA::delete', false],
    ['\APP\Models\**\*::DELETE*', '\app\models\User::delete', true],
    ['App\**\Services\**\*::delete', 'App\Services\User::delete', true],
    ['App\**\Services\**\*::delete', 'App\Module\Services\Nested\User::delete', true],
    ['App\*::delete*', 'App\User::delete', true],
    ['App\*::delete*', 'App\Admin\User::delete', false],
]);

it('rejects invalid recursive and unsupported glob syntax', function (string $pattern): void {
    expect(fn () => new CriticalOperationMatcher([$pattern]))->toThrow(InvalidArgumentException::class);
})->with([
    'App\Mod**els\*::delete', 'App\**::delete', 'Class::**',
    'App\**\**\*::delete', 'App\***\*::delete', 'App\*::del**ete',
    'App\*::delete?', 'App\[AB]*::delete', 'App\{A,B}::delete',
    'App\1*::delete', 'App\*::1delete*', 'App\\\*::delete',
    'App\**\delete*', 'App\*::delete::extra',
]);

it('applies recursive and partial exclusions before every inclusion', function (bool $exclusionFirst): void {
    $operations = ['App\Models\**\*::delete*', 'App\Models\Legacy\User::delete'];
    $exclusion = '!App\Models\Legacy\**\*::delete*';
    if ($exclusionFirst) {
        array_unshift($operations, $exclusion);
    } else {
        $operations[] = $exclusion;
    }
    $matcher = new CriticalOperationMatcher($operations);

    expect($matcher->match('App\Models\Legacy\User::delete'))->toBeNull()
        ->and($matcher->match('App\Models\Legacy\Admin\User::deleteAccount'))->toBeNull()
        ->and($matcher->match('App\Models\Admin\User::delete'))->toBe('App\Models\Admin\User::delete')
        ->and($matcher->matchAny(['App\Models\Admin\User::delete', 'App\Models\Legacy\User::delete']))->toBeNull();
})->with([true, false]);

it('explains malformed glob syntax', function (): void {
    expect(fn () => new CriticalOperationMatcher(['App\Mod**els\*::delete']))
        ->toThrow(InvalidArgumentException::class, 'CWE-306 critical operations must be function names or Class::method names. Use * within identifiers, ** for complete namespace segments, and ! before exclusion patterns.');
});
