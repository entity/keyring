<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
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
use Keyring\Login\Verification;
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

    // A route keeps its controller once it has made one, and in a worker
    // that serves many requests that can be longer than a request lasts.
    // These hold the session they were made for, or reach something that
    // does, so they're asked of the app handling the request each time.
    protected AttemptStore $attempts { get => app(AttemptStore::class); }

    protected StepUp $stepUp { get => app(StepUp::class); }

    protected Verifier $verifier { get => app(Verifier::class); }

    public function __construct(
        protected KeyringManager $keyring,
        protected Throttle $throttle,
    ) {}

    public function show(Request $request, ?string $factor = null): mixed
    {
        $purpose = $this->purpose($request);
        $current = $this->attempts->current($purpose);
        $attempt = $current ?? ($purpose === Purpose::Confirm ? $this->confirming($request) : null);

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
            // Once enrolled, they carry on to the page the confirm was for,
            // if they were sent here for one: on a visit of their own,
            // url.intended is whatever someone last left in it. It's handed
            // back once the account can meet what the confirm asks.
            return $purpose === Purpose::Confirm
                ? $this->stepUp->enrollFirst($request, $current === null ? null : $this->confirmingFor($request), $attempt->requirement)
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
            'authenticator' => $this->option($authenticator),
            'challenge' => $challenge,
            'alternatives' => $options
                ->reject(fn (Authenticator $option) => $option->id === $authenticator->id)
                ->map($this->option(...))
                ->values()
                ->all(),
            'canTrustDevice' => $this->canTrustDevice($attempt, $authenticator),
            'expiresAt' => date(DATE_ATOM, $attempt->expiresAt),
        ]);
    }

    /**
     * An authenticator as the challenge page offers it: what tells it from
     * the others, without when it was added or last used. At sign in the
     * page is shown to whoever has the password, who has no call to learn
     * when its owner was last here.
     *
     * @return array<string, mixed>
     */
    protected function option(Authenticator $authenticator): array
    {
        return Arr::except($authenticator->factor()->present($authenticator), ['createdAt', 'lastUsedAt']);
    }

    /**
     * Whether "don't ask again on this device" could be earned here. Trust
     * takes a login that proved two factors, which an emailed code beside
     * a password doesn't.
     */
    protected function canTrustDevice(Attempt $attempt, Authenticator $authenticator): bool
    {
        return $attempt->purpose === Purpose::Login
            && Features::enabled(Features::devices())
            && config('keyring.devices.trust_for') !== null
            && Requirement::aal2()->isMetBy([...$attempt->verifications, Verification::of($authenticator)]);
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

        $this->throttle->sending($factor->key(), $attempt->user());

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
     * The page a confirm is for: where ConfirmationRequiredResponse said to
     * come back to.
     */
    protected function confirmingFor(Request $request): ?string
    {
        $url = $request->session()->get('url.intended');

        return is_string($url) ? $url : null;
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
