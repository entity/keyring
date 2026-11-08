<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Timebox;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\FactorFailed;
use Keyring\Events\FactorVerified;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Verification;
use Keyring\Pipeline\Context;
use Keyring\Testing\KeyringFake;

/**
 * Identifies the user (for primary factors) and checks the proof, inside a
 * timebox so failures and unknown users take the same time.
 */
class VerifyFactor
{
    public function __construct(
        protected Container $container,
        protected AttemptStore $attempts,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        if (! $this->faked($context)) {
            $context->request->validate($this->rules($context));
        }

        $this->container->make(Timebox::class)->call(function (Timebox $timebox) use ($context) {
            if ($context->identifying && $context->factor instanceof PrimaryFactor) {
                $context->authenticator = $context->factor->identify($context->request);

                if ($context->authenticator !== null) {
                    $context->attempt = Attempt::start(
                        $context->purpose,
                        $context->authenticator->user(),
                        $context->request->boolean('remember'),
                    );
                }
            }

            if ($context->attempt === null || $context->authenticator === null) {
                return;
            }

            $context->verification = $this->check($context);

            if ($context->verification !== null) {
                $timebox->returnEarly();
            }
        }, config('keyring.timebox'));

        if ($context->verification === null) {
            FactorFailed::dispatch($context->attempt, $context->authenticator, $context->factor->key(), $context->request);

            // Keep factor state, like a code's remaining guesses.
            if (! $context->identifying && $context->attempt !== null) {
                $this->attempts->save($context->attempt);
            }

            return $context->fail();
        }

        $context->attempt->record($context->verification);

        // A factor may verify a different authenticator than the one shown
        // (e.g. the user tapped another of their security keys).
        if ($context->verification->authenticator !== null && $context->verification->authenticator !== $context->authenticator->id) {
            $context->authenticator = $context->attempt->keyring()->find($context->verification->authenticator) ?? $context->authenticator;
        }

        $context->authenticator->markAsUsed();

        FactorVerified::dispatch($context->attempt, $context->authenticator, $context->verification);

        return $next($context);
    }

    protected function faked(Context $context): bool
    {
        return $this->container->bound(KeyringFake::class)
            && $this->container->make(KeyringFake::class)->decision($context->factor->key()) !== null;
    }

    protected function check(Context $context): ?Verification
    {
        $decision = $this->container->bound(KeyringFake::class)
            ? $this->container->make(KeyringFake::class)->decision($context->factor->key())
            : null;

        if ($decision === null) {
            return $context->factor->verify($context->attempt, $context->authenticator, $context->request);
        }

        return $decision ? Verification::of($context->authenticator) : null;
    }

    /**
     * @return array<string, mixed>
     */
    protected function rules(Context $context): array
    {
        return [
            ...($context->identifying && $context->factor instanceof PrimaryFactor ? $context->factor->identificationRules() : []),
            ...$context->factor->rules(),
        ];
    }
}
