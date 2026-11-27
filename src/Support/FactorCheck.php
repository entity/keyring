<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Purpose;
use Keyring\Events\AccountLocked;
use Keyring\Events\FactorFailed;
use Keyring\Events\Lockout;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;
use Throwable;

/**
 * One factor checked inside a request that does something else, such as
 * the password that adds a first second factor, or the key that makes a
 * change while the account is frozen. It runs under the factor's rate
 * limits, and a failure counts and goes on record, as a step-up's would.
 */
class FactorCheck
{
    public function __construct(
        protected Throttle $throttle,
    ) {}

    /**
     * The authenticator, of those given, that the input proves, or null when
     * it proves none of them. A refusal by the rate limits is an error on
     * $field, answered as a sign in's would be, and goes on record as a
     * Lockout. A failure that gets a factor that can start a sign in
     * refused until its limits are cleared tells the user, as a sign in's
     * would (AccountLocked).
     *
     * @param  Collection<int, Authenticator>  $authenticators  the first is the one the factor is shown
     * @param  array<string, mixed>  $input  what the factor reads its answer from
     *
     * @throws ValidationException
     */
    public function check(Request $request, Attempt $attempt, Factor $factor, Collection $authenticators, #[\SensitiveParameter] array $input, string $field): ?Authenticator
    {
        $authenticator = $authenticators->firstOrFail();
        $limits = $this->throttle->aim($factor->limits($request, $attempt), new Context($request, Purpose::Confirm, $factor, $attempt, $authenticator));

        if (($refusing = $this->throttle->hit($limits)) !== null) {
            $retryAfter = $this->throttle->retryAfter($refusing);

            Lockout::dispatch($request, $factor->key(), $retryAfter);

            throw Throttle::lockedOut($factor, $field, $retryAfter);
        }

        try {
            // The factor reads its answer where it always does.
            $verification = $factor->verify($attempt, $authenticator, Request::create('/', 'POST', $input));
        } catch (Throwable $e) {
            $this->throttle->release($limits);

            throw $e;
        }

        // A key may answer for another of the user's: it only counts when
        // that's one of these.
        $used = $verification === null ? null : $authenticators->firstWhere('id', '===', $verification->authenticator ?? $authenticator->id);

        if ($used === null) {
            if ($this->throttle->failed($limits) && $factor instanceof PrimaryFactor && $factor->startsLogin()) {
                AccountLocked::dispatch($attempt->user(), $factor->key());
            }

            FactorFailed::dispatch($attempt, $authenticator, $factor->key(), $request);

            return null;
        }

        $this->throttle->succeeded($limits);

        return $used;
    }
}
