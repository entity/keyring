<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;

/**
 * A code emailed to the user's current address. Opt-in only: NIST SP 800-63B
 * rules out email for authentication codes, and whoever controls the inbox
 * can reset the password too, so for a user whose only second factor it is,
 * the inbox is the whole account. Register EmailCode::asSecondFactor() to
 * accept that.
 */
class EmailCode extends CodeFactor
{
    final public function __construct(bool $acceptRisk = false)
    {
        if (! $acceptRisk) {
            throw new InvalidArgumentException(
                'Email codes don\'t meet NIST SP 800-63B as a second factor: email isn\'t an accepted channel, '
                .'and whoever controls the inbox can also reset the password. Register EmailCode::asSecondFactor() to accept them anyway.',
            );
        }
    }

    /**
     * Accept email codes as a second factor, knowing they fall short of NIST
     * AAL2.
     */
    public static function asSecondFactor(): static
    {
        return new static(acceptRisk: true);
    }

    public const string KEY = 'email-code';

    public function key(): string
    {
        return self::KEY;
    }

    public function present(Authenticator $authenticator): array
    {
        return [...parent::present($authenticator), 'hint' => $this->mask((string) $authenticator->user()->getAttribute('email'))];
    }

    /**
     * Every copy would go to the same address, so one is enough.
     */
    public function multiple(): bool
    {
        return false;
    }

    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void
    {
        // An authenticator that isn't saved yet means this code confirms enrollment.
        Notification::send($user, app(VerificationCode::class, ['code' => $code, 'ttl' => $this->ttl, 'enrolling' => ! $authenticator->exists]));
    }

    protected function defaultName(Authenticatable&Model $user): string
    {
        return __('Email');
    }

    protected function mask(string $email): string
    {
        [$local, $domain] = array_pad(explode('@', $email, 2), 2, '');

        return Str::substr($local, 0, 1).'•••@'.$domain;
    }
}
