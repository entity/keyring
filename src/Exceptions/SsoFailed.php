<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Keyring\Enums\SsoFailure;
use RuntimeException;

/**
 * Every way a sign in through an identity provider can fail, told apart by
 * its reason. The message says which check failed and never carries a
 * code, token or secret, so it's safe to log. What the provider's response
 * said isn't kept either: an error body from a token endpoint can echo
 * what was sent to it.
 */
class SsoFailed extends RuntimeException
{
    public function __construct(
        public readonly SsoFailure $reason,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function because(SsoFailure $reason, string $detail): self
    {
        return new self($reason, "Single sign-on failed ({$reason->value}): {$detail}");
    }

    /**
     * Whether it's a failure users bring about every day, which says
     * nothing is wrong: they said no at the provider, or came back with a
     * state that's spent, expired, or another browser's. Keyring reports
     * every other one, so a wrong secret or a clock that's off shows up in
     * the app's logs.
     */
    public function expected(): bool
    {
        return in_array($this->reason, [SsoFailure::Denied, SsoFailure::InvalidState], true);
    }
}
