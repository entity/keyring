<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Notification;
use InvalidArgumentException;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;
use Keyring\Support\MailText;

/**
 * A code emailed to the user's current address. Opt-in only: whoever controls
 * the inbox can reset the password too, so for a user whose only second
 * factor it is, the inbox is the whole account. Register
 * EmailCode::asSecondFactor() to accept that.
 */
class EmailCode extends CodeFactor
{
    final public function __construct(bool $acceptRisk = false)
    {
        if (! $acceptRisk) {
            throw new InvalidArgumentException(
                'Email codes are a weak second factor: whoever controls the inbox can also reset the password. '
                .'Register EmailCode::asSecondFactor() to accept them anyway.',
            );
        }
    }

    /**
     * Accept email codes as a second factor, knowing they fall short of AAL2.
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
        return [...parent::present($authenticator), 'hint' => MailText::maskAddress((string) $authenticator->user()->getAttribute('email'))];
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
}
