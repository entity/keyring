<?php

namespace Keyring\Facades;

use Illuminate\Support\Facades\Facade;
use Keyring\KeyringManager;

/**
 * @method static \Keyring\KeyringManager factors(array $factors)
 * @method static \Keyring\KeyringManager extend(string $key, \Closure $resolver)
 * @method static \Keyring\Contracts\Factor factor(string $key)
 * @method static bool hasFactor(string $key)
 * @method static \Illuminate\Support\Collection registered()
 * @method static \Keyring\KeyringManager require(\Closure|\Keyring\Login\Requirement $policy)
 * @method static \Keyring\Login\Requirement policy(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, \Keyring\Login\Attempt $attempt)
 * @method static \Keyring\Login\Requirement requirementFor(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, \Keyring\Login\Attempt $attempt)
 * @method static \Keyring\KeyringManager page(string $name, \Closure|string $component)
 * @method static mixed render(string $name, array $props = [])
 * @method static void routes()
 * @method static \Keyring\KeyringManager pipeline(\Closure $callback)
 * @method static array steps()
 * @method static \Keyring\Risk\RiskEngine risk(array|null $signals = null)
 * @method static \Keyring\KeyringManager notify(array|null $types = null)
 * @method static bool notifies(string $type)
 * @method static \Keyring\Testing\KeyringFake fake()
 * @method static \Keyring\KeyringManager securityNoticesUsing(string $notification)
 * @method static \Keyring\KeyringManager createUsersUsing(string $action)
 * @method static \Keyring\KeyringManager resetUserPasswordsUsing(string $action)
 * @method static \Keyring\KeyringManager updateUserPasswordsUsing(string $action)
 * @method static \Keyring\KeyringManager validateEmailChangesUsing(string $action)
 * @method static \Illuminate\Support\Collection activity(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user, int $limit = 25)
 * @method static string|null statusMessage(mixed $status)
 * @method static \Keyring\KeyringManager respondWith(string $contract, \Closure|string $implementation)
 * @method static \Illuminate\Contracts\Auth\StatefulGuard guard()
 * @method static \Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model user()
 * @method static \Illuminate\Contracts\Auth\UserProvider provider(string|null $guard = null)
 * @method static bool belongsToGuard(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static \Keyring\UserKeyring for(\Illuminate\Contracts\Auth\Authenticatable&\Illuminate\Database\Eloquent\Model $user)
 * @method static string username()
 * @method static string normalizeUsername(string $username)
 * @method static \Keyring\KeyringManager normalizeUsernamesUsing(\Closure $callback)
 * @method static \Keyring\KeyringManager findUsersUsing(\Closure $callback)
 * @method static \Keyring\KeyringManager signInAfterRegistering(\Closure|bool $when)
 * @method static array protectedAttributes()
 * @method static mixed withoutProtection(\Closure $callback, string|null $reason = null)
 * @method static \Keyring\KeyringManager useAuthenticatorModel(string $model)
 * @method static class-string<\Keyring\Models\Authenticator> authenticatorModel()
 * @method static \Keyring\KeyringManager useDeviceModel(string $model)
 * @method static class-string<\Keyring\Models\Device> deviceModel()
 * @method static \Keyring\KeyringManager usePendingChangeModel(string $model)
 * @method static class-string<\Keyring\Models\PendingChange> pendingChangeModel()
 * @method static \Keyring\KeyringManager useSecurityEventModel(string $model)
 * @method static class-string<\Keyring\Models\SecurityEvent> securityEventModel()
 *
 * @see KeyringManager
 */
class Keyring extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return KeyringManager::class;
    }
}
