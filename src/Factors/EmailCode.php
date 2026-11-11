<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Notification;
use InvalidArgumentException;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Support\Duration;
use Keyring\Support\MailText;

/**
 * A code emailed to the user's current address. Opt-in only: whoever controls
 * the inbox can reset the password too, so for a user whose only second
 * factor it is, the inbox is the whole account. Register
 * EmailCode::asSecondFactor() to accept that.
 */
class EmailCode extends CodeFactor
{
    public const string KEY = 'email-code';

    final public function __construct(bool $acceptRisk = false, ?int $length = null, ?string $expireAfter = null, ?int $maxGuesses = null)
    {
        if (! $acceptRisk) {
            throw new InvalidArgumentException(
                'Email codes are a weak second factor: whoever controls the inbox can also reset the password. '
                .'Register EmailCode::asSecondFactor() to accept them anyway.',
            );
        }

        $this->length = $length ?? $this->length;
        $this->ttl = $expireAfter === null ? $this->ttl : Duration::seconds($expireAfter);
        $this->maxGuesses = $maxGuesses ?? $this->maxGuesses;

        // Here as well as when it's registered, so the line that asked for
        // a code too short or too long-lived is the one that fails.
        $this->ensureCodesAreSafe();
    }

    /**
     * Accept email codes as a second factor, knowing they fall short of AAL2.
     * Eight digits, good for ten minutes and five wrong guesses, unless you
     * say otherwise: EmailCode::asSecondFactor(length: 6, expireAfter: '5m').
     * Six digits is the fewest and ten minutes the longest Keyring allows.
     */
    public static function asSecondFactor(?int $length = null, ?string $expireAfter = null, ?int $maxGuesses = null): static
    {
        return new static(true, $length, $expireAfter, $maxGuesses);
    }

    public function key(): string
    {
        return self::KEY;
    }

    public function present(Authenticator $authenticator): array
    {
        return [...parent::present($authenticator), 'hint' => MailText::maskAddress((string) $authenticator->user()->getAttribute(Keyring::email()))];
    }

    /**
     * Every copy would go to the same address, so one is enough.
     */
    public function multiple(): bool
    {
        return false;
    }

    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, #[\SensitiveParameter] string $code): void
    {
        // An authenticator that isn't saved yet means this code confirms enrollment.
        Notification::send($user, Keyring::requiredNotification('verification_code', [
            'code' => $code,
            'minutes' => intdiv($this->ttl, 60),
            'enrolling' => ! $authenticator->exists,
        ]));
    }

    protected function defaultName(Authenticatable&Model $user): string
    {
        return __('Email');
    }
}
