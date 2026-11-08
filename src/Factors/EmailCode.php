<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;

/**
 * A code emailed to the user's current address. Only as strong as their
 * inbox, so policies shouldn't treat it as phishing resistant.
 */
class EmailCode extends CodeFactor
{
    public function key(): string
    {
        return 'email-code';
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
