<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keyring\Contracts\SendsCodes;
use Keyring\Enums\Purpose;
use Keyring\Events\FactorChallenged;
use Keyring\Features;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Verifier;
use Keyring\Support\Throttle;

/**
 * One controller for every factor and both purposes (login and step-up).
 * Adding a factor never needs a new route.
 */
class ChallengeController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected AttemptStore $attempts,
        protected StepUp $stepUp,
        protected Throttle $throttle,
        protected Verifier $verifier,
    ) {}

    public function show(Request $request, ?string $factor = null): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose)
            ?? ($purpose === Purpose::Confirm ? $this->confirming($request) : null);

        if ($attempt === null) {
            return $this->expired($request, $purpose);
        }

        if ($attempt->exhausted) {
            return $this->startOver($request, $purpose);
        }

        $options = $attempt->options();

        if ($options->isEmpty()) {
            $this->attempts->forget($purpose);

            // With nothing to confirm with, coming back here would only loop.
            return $purpose === Purpose::Confirm
                ? $this->stepUp->enrollFirst($request)
                : $this->expired($request, $purpose, __('keyring::keyring.unavailable'));
        }

        $authenticator = $this->choose($attempt, $options, $factor, $request->query('authenticator'));

        if ($authenticator === null) {
            return to_route("keyring.{$purpose->value}.challenge");
        }

        $attempt->present($authenticator);
        $challenge = $authenticator->factor()->challenge($attempt, $authenticator);
        $this->attempts->save($attempt);

        FactorChallenged::dispatch($attempt, $authenticator);

        return $this->keyring->render($purpose === Purpose::Login ? 'challenge' : $purpose->value, [
            'purpose' => $purpose->value,
            'factor' => $authenticator->factor,
            'authenticator' => $authenticator->factor()->present($authenticator),
            'challenge' => $challenge,
            'alternatives' => $options
                ->reject(fn (Authenticator $option) => $option->id === $authenticator->id)
                ->map(fn (Authenticator $option) => $option->factor()->present($option))
                ->values()
                ->all(),
            'canTrustDevice' => $purpose === Purpose::Login && Features::enabled(Features::devices()) && config('keyring.devices.trust_for') !== null,
            'expiresAt' => date(DATE_ATOM, $attempt->expiresAt),
        ]);
    }

    /**
     * Send a code for factors that need one. Separate from viewing the page,
     * so prefetching or reloading never sends anything.
     */
    public function send(Request $request, string $factor): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose);

        if ($attempt === null) {
            return $this->expired($request, $purpose);
        }

        if ($attempt->exhausted) {
            return $this->startOver($request, $purpose);
        }

        $factor = $this->keyring->factor($factor);
        abort_unless($factor instanceof SendsCodes, 404);

        $authenticator = $this->authenticatorFor($request, $attempt, $factor->key()) ?? abort(404);

        $this->throttle->sending($factor->key(), $attempt->userId);

        $factor->send($attempt, $authenticator);

        // Sending found the attempt out of guesses, where this copy of the
        // session didn't know it.
        if ($attempt->exhausted) {
            return $this->startOver($request, $purpose);
        }

        $this->attempts->save($attempt);

        return $this->status('code-sent');
    }

    public function verify(Request $request, string $factor): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose);

        if ($attempt === null) {
            return $this->expired($request, $purpose);
        }

        $factor = $this->keyring->factor($factor);

        // Out of guesses, nothing can finish this attempt. Failing it here
        // instead of refusing keeps the account's counters counting.
        $authenticator = $attempt->exhausted ? null : $this->authenticatorFor($request, $attempt, $factor->key());

        return $this->verifier->respond(new Context($request, $purpose, $factor, $attempt, $authenticator));
    }

    /**
     * The authenticator a request is aimed at: the one it names, the one the
     * page showed, or the only one of that factor.
     */
    protected function authenticatorFor(Request $request, Attempt $attempt, string $factor): ?Authenticator
    {
        return $this->pick($attempt, $attempt->options(), $factor, $request->input('authenticator'), strict: true);
    }

    /**
     * The authenticator to show: the one asked for, else the default.
     *
     * @param  Collection<int, Authenticator>  $options
     */
    protected function choose(Attempt $attempt, Collection $options, ?string $factor, mixed $id): ?Authenticator
    {
        return $factor === null
            ? $options->firstWhere('is_default', true) ?? $options->first()
            : $this->pick($attempt, $options, $factor, $id, strict: false);
    }

    /**
     * The option with the given (or last presented) ID for the factor. With
     * no match, showing a page can fall back to the first, but verifying only
     * falls back when there's no doubt which one is meant.
     *
     * @param  Collection<int, Authenticator>  $options
     */
    protected function pick(Attempt $attempt, Collection $options, string $factor, mixed $id, bool $strict): ?Authenticator
    {
        $candidates = $options->where('factor', '===', $factor);

        return $candidates->firstWhere('id', '===', $id ?? $attempt->presented($factor))
            ?? (! $strict || $candidates->count() === 1 ? $candidates->first() : null);
    }

    /**
     * The same controller serves keyring.login.* and keyring.confirm.*.
     */
    protected function purpose(Request $request): Purpose
    {
        return $request->routeIs('keyring.login.*') ? Purpose::Login : Purpose::Confirm;
    }

    /**
     * A code was guessed too many times, so drop the attempt: the only way on
     * is to start again.
     */
    protected function startOver(Request $request, Purpose $purpose): RedirectResponse
    {
        $this->attempts->forget($purpose);

        return $this->expired($request, $purpose, __('keyring::keyring.too_many_codes'));
    }

    /**
     * Back to the start, with the reason on a field that page has: the
     * username on the login page, and whatever the confirm page asks for next.
     */
    protected function expired(Request $request, Purpose $purpose, ?string $message = null): RedirectResponse
    {
        $message ??= __('keyring::keyring.expired');

        if ($purpose === Purpose::Login) {
            return to_route('login')->withErrors([$this->keyring->username() => $message]);
        }

        $attempt = $this->confirming($request);
        $next = $this->choose($attempt, $attempt->options(), null, null);

        return to_route('keyring.confirm.challenge')
            ->withErrors([$next?->factor()->errorKey() ?? $this->keyring->username() => $message]);
    }

    /**
     * The confirm attempt in progress, or a new one for visiting the confirm
     * page without being sent there.
     */
    protected function confirming(Request $request): Attempt
    {
        return $this->stepUp->begin($request, Requirement::aal1()->withoutRecoveryCodes());
    }
}
