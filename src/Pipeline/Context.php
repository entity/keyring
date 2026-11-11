<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use Illuminate\Http\Request;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Purpose;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use LogicException;

/**
 * What travels through the verification pipeline.
 */
final class Context
{
    public ?Verification $verification = null;

    public ?Outcome $outcome = null;

    /** Seconds until a rate limit that refused the request lets one through. Null when waiting won't do it. */
    public ?int $retryAfter = 0;

    /** Whether the rate limits were checked for this request. */
    public bool $throttleChecked = false;

    /** Whether a rate limit refused this request without saying so. */
    public bool $refused = false;

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

    /**
     * The attempt being verified. There's one from VerifyFactor onwards: it
     * starts the attempt when a primary factor identifies the user.
     */
    public function attempt(): Attempt
    {
        return $this->attempt ?? throw new LogicException('This step needs the attempt, so it has to run after VerifyFactor.');
    }

    /**
     * The authenticator being verified, known from VerifyFactor onwards.
     */
    public function authenticator(): Authenticator
    {
        return $this->authenticator ?? throw new LogicException('This step needs the authenticator, so it has to run after VerifyFactor.');
    }

    public function fail(): self
    {
        $this->outcome = Outcome::Failed;

        return $this;
    }

    public function lockout(?int $retryAfter): self
    {
        $this->outcome = Outcome::LockedOut;
        $this->retryAfter = $retryAfter;

        return $this;
    }

    /**
     * A rate limit refused the request without saying so. It carries on down
     * the pipeline and fails like a wrong proof, which is never looked at.
     */
    public function refuse(?int $retryAfter): self
    {
        $this->refused = true;
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
