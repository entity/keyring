<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Factors\CodeFactor;
use Keyring\Models\Authenticator;

/**
 * A custom code factor, written the way the docs suggest.
 */
class SmsCode extends CodeFactor
{
    /** @var array<string, string> Phone number => last code sent. */
    public static array $sent = [];

    public function key(): string
    {
        return 'sms';
    }

    protected function defaultName(Authenticatable&Model $user): string
    {
        return 'Phone';
    }

    protected function newAuthenticator(Authenticatable&Model $user, Request $request): Authenticator
    {
        return parent::newAuthenticator($user, $request)->forceFill(['secret' => $request->string('phone')->value()]);
    }

    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void
    {
        static::$sent[(string) $authenticator->secret] = $code;
    }
}
