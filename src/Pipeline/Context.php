<?php

namespace Keyring\Pipeline;

use Illuminate\Http\Request;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Purpose;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * What travels through the verification pipeline.
 */
final class Context
{
    public ?Verification $verification = null;

    public ?Outcome $outcome = null;

    public int $retryAfter = 0;

    /** Whether the rate limits were checked for this request. */
    public bool $throttleChecked = false;

    /** Whether the risk lock was checked for this request. */
    public bool $riskLockChecked = false;

    /** Whether this request also identifies the user (a primary factor starting a login). */
    public readonly bool $identifying;

    public function __construct(
        public readonly Request $request,
        public readonly Purpose $purpose,
        public readonly Factor $factor,
        public ?Attempt $attempt = null,
        public ?Authenticator $authenticator = null,
    ) {
        $this->identifying = $attempt === null && $factor instanceof PrimaryFactor;
    }

    public function fail(): self
    {
        $this->outcome = Outcome::Failed;

        return $this;
    }

    public function lockout(int $retryAfter): self
    {
        $this->outcome = Outcome::LockedOut;
        $this->retryAfter = $retryAfter;

        return $this;
    }

    /**
     * The form field to report problems on: the first identifying field (like
     * the email) when starting a login, otherwise the factor's own field.
     */
    public function errorKey(): string
    {
        if ($this->identifying && $this->factor instanceof PrimaryFactor) {
            return array_key_first($this->factor->identificationRules()) ?? $this->factor->errorKey();
        }

        return $this->factor->errorKey();
    }
}
