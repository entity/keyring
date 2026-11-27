<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\FreezeSkips;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\SendsCodes;
use Keyring\Enrollment\Enrollment;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Events\EnrollmentRefused;
use Keyring\Exceptions\SignInChangesFrozen;
use Keyring\Factors\Factor;
use Keyring\Factors\RecoveryCodes;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\Detours;
use Keyring\Login\SignIn;
use Keyring\Models\Authenticator;
use Keyring\Sessions\Sessions;
use Keyring\Support\Input;
use Keyring\Support\Throttle;

/**
 * Adding, renaming, choosing the default and removing authenticators. One
 * set of routes for every factor.
 */
class AuthenticatorController
{
    use RespondsWithStatus;

    /** On an enrollment begun with a proof that let it past the freeze. */
    protected const string PROVED = 'keyring.freeze_skipped';

    /**
     * On an enrollment begun with the password, where adding it takes one.
     * A link to an identity provider, which its callback finishes, reads it
     * there.
     */
    public const string PASSWORD_CONFIRMED = 'keyring.password_confirmed';

    // A route keeps its controller once it has made one, and in a worker
    // that serves many requests that can be longer than a request lasts.
    // These hold the session they were made for, or reach something that
    // does, so they're asked of the app handling the request each time.
    protected EnrollmentStore $enrollments { get => app(EnrollmentStore::class); }

    protected SignIn $signIn { get => app(SignIn::class); }

    protected Detours $detours { get => app(Detours::class); }

    public function __construct(
        protected KeyringManager $keyring,
        protected AuthenticatorChanges $changes,
        protected Throttle $throttle,
        protected Sessions $sessions,
        protected FreezeSkips $skips,
    ) {}

    /**
     * Begin enrolling: returns what the user needs to see (QR code, codes...).
     *
     * Everything that could stop the confirm is asked for here, so the user
     * isn't shown a code or a QR code that can't be saved: the password,
     * when the account has no established second factor yet ("password"),
     * and a proof of an established method, when it would replace one
     * while the account is frozen ("proof"). The enrollment remembers both,
     * and its one confirm uses them.
     */
    public function store(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);
        $user = $this->keyring->user();

        // A name given now is kept for the confirm, which may not send one.
        // Anything that isn't text is left out of it, as before.
        Input::validate($request, ['name' => [Factor::validText()], 'password' => ['nullable', 'string']]);

        $passwordConfirmed = $this->changes->needsPassword($user, $factor);

        if ($passwordConfirmed) {
            $this->changes->confirmPassword($user, $factor, $request, Input::get($request, 'password'));
        }

        $proved = $this->skips->proves($user, $request, 'replace', $factor->key());

        if (! $proved) {
            $this->skippable($request, fn () => $this->changes->ensureMayAdd($user, $factor));
        }

        // Enrolling a code factor sends a code, wherever the user asks for it to go.
        if ($factor instanceof SendsCodes) {
            $this->throttle->sending($factor->key(), $this->keyring->user());
        }

        $enrollment = $factor->beginEnrollment($this->keyring->user(), $request);

        $this->enrollments->put($enrollment->with(static::PROVED, $proved)->with(static::PASSWORD_CONFIRMED, $passwordConfirmed));

        return $this->status('enrollment-started', ['factor' => $factor->key(), 'enrollment' => $enrollment->props]);
    }

    /**
     * Finish enrolling once the user proves it works. What let it past the
     * freeze, or took the password, was given when it began. When it's
     * refused anyway, because the account changed since, the enrollment is
     * spent, and the client begins again with what it now needs.
     */
    public function confirm(Request $request, string $factor): StatusResponse
    {
        $factor = $this->enrollable($request, $factor);

        $enrollment = $this->enrollments->get($factor->key())
            ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);

        Input::validate($request, [...$factor->enrollmentRules(), 'sign_out_others' => ['sometimes', 'boolean']]);

        $authenticator = $this->confirmed($factor, $enrollment, $request);

        // Each enrollment adds its authenticator once, whichever copy of the
        // session it comes back in.
        if (! $this->enrollments->claim($enrollment)) {
            throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.enrollment_expired')]);
        }

        try {
            $recoveryCodes = $this->skippable($request, fn () => $this->changes->add(
                $this->keyring->user(),
                $factor,
                $authenticator,
                $request,
                ignoreFreeze: $enrollment->state(static::PROVED) === true,
                passwordConfirmed: $enrollment->state(static::PASSWORD_CONFIRMED) === true,
            ));
        } finally {
            $this->enrollments->forget($factor->key());
        }
        $this->signOutOthers($request);

        // New recovery codes prove nothing: confirming only says they were
        // saved. Anything else was just proved to work.
        if ($factor->key() !== RecoveryCodes::KEY) {
            $this->signIn->enrolled($request, $authenticator);
        }

        // Where they were going when sent here, as data rather than a
        // redirect: a page with new recovery codes on it has to stay up
        // until they're saved. It only comes back once the account can meet
        // what sent them here, so an emailed code, which isn't a second
        // factor, leaves it saved for one that is. New recovery codes meet
        // no requirement, so they'd only be sent back here.
        return $this->status('authenticator-added', array_filter([
            'authenticator' => $authenticator->factor()->present($authenticator),
            'recoveryCodes' => $recoveryCodes,
            'continue' => $factor->key() === RecoveryCodes::KEY ? null : $this->detours->pull($request, Detours::ENROLLMENT),
        ]));
    }

    /**
     * Rename an authenticator, or choose the default. While the account is
     * frozen, renaming an established one takes a proof of an established
     * method, for giving this one this name.
     */
    public function update(Request $request, string $authenticator): StatusResponse
    {
        $authenticator = $this->changes->find($this->keyring->user(), $authenticator);
        $factor = $authenticator->factor();

        $changes = $request->validate([
            'name' => ['sometimes', ...Factor::nameRules()],
            // The default is what the challenge page asks for first. Recovery
            // codes are a fallback, never that, and a factor that never
            // answers a challenge, like an identity provider, can't be.
            'default' => ['sometimes', 'boolean', Rule::prohibitedIf($factor->key() === RecoveryCodes::KEY || ($factor instanceof PrimaryFactor && ! $factor->answersChallenges()))],
        ]);

        $proved = array_key_exists('name', $changes) && $this->skips->proves($this->keyring->user(), $request, 'rename', $authenticator->id, $changes['name']);

        $this->skippable($request, fn () => $this->changes->update($authenticator, [
            ...Arr::only($changes, 'name'),
            ...$request->has('default') ? ['default' => $request->boolean('default')] : [],
        ], ignoreFreeze: $proved));

        return $this->status('authenticator-updated', ['authenticator' => $factor->present($authenticator)]);
    }

    public function destroy(Request $request, string $authenticator): StatusResponse
    {
        // Only asked for when this is the last second factor.
        Input::validate($request, ['password' => ['nullable', 'string'], 'sign_out_others' => ['sometimes', 'boolean']]);

        // A proof of an established method, for removing this one, lets it
        // past the freeze.
        $proved = $this->skips->proves($this->keyring->user(), $request, 'remove', $authenticator);

        $this->skippable($request, fn () => $this->changes->remove($this->keyring->user(), $authenticator, Input::get($request, 'password'), ignoreFreeze: $proved));
        $this->signOutOthers($request);

        return $this->status('authenticator-removed');
    }

    /**
     * A challenge for one of the user's established authenticators of this
     * factor to answer, to make one change while the account is frozen:
     * "remove" an authenticator (its ID as "target"), "rename" one to
     * "name", or "replace" a factor's (its key). The change's own request
     * then sends the answer as "proof". For a key, it's the options its
     * browser signs.
     */
    public function proofOptions(Request $request, string $factor): JsonResponse
    {
        $change = Input::validate($request, [
            'action' => ['required', 'string', Rule::in(FreezeSkips::ACTIONS)],
            'target' => ['required', 'string', 'max:255'],
            'name' => ['required_if:action,rename', 'prohibited_unless:action,rename', ...Factor::nameRules()],
        ]);

        return new JsonResponse($this->skips->options($this->keyring->user(), $request, $factor, $change['action'], $change['target'], $change['name'] ?? null));
    }

    /**
     * Run a change, and when it's refused for the freeze, say which factors
     * could prove it now.
     *
     * @template T
     *
     * @param  Closure(): T  $change
     * @return T
     */
    protected function skippable(Request $request, Closure $change): mixed
    {
        try {
            return $change();
        } catch (SignInChangesFrozen $e) {
            throw $e->skippableWith($this->skips->factors($this->keyring->user(), $request));
        }
    }

    /**
     * Someone else being signed in is often why a user changes how they
     * sign in, so the change can take the other sessions out with it
     * ("sign_out_others"), keeping this one. Unlike a password change it has
     * to be asked for: a new passkey takes nothing away from a session that
     * signed in without it.
     */
    protected function signOutOthers(Request $request): void
    {
        if ($request->boolean('sign_out_others')) {
            $this->sessions->signOutOthers($request, $this->keyring->user());
        }
    }

    /**
     * The authenticator the user just proved works. A proof the factor
     * turns down is answered as before and goes on record, whether the
     * factor says no or throws its own message.
     *
     * @throws ValidationException
     */
    protected function confirmed(Enrollable $factor, Enrollment $enrollment, Request $request): Authenticator
    {
        try {
            return $factor->confirmEnrollment($this->keyring->user(), $enrollment, $request)
                ?? throw ValidationException::withMessages([$factor->errorKey() => __('keyring::keyring.invalid')]);
        } catch (ValidationException $e) {
            EnrollmentRefused::dispatch($this->keyring->user(), $factor->key(), 'invalid');

            throw $e;
        }
    }

    /**
     * The factor to enroll. Until the email address is proven, the account
     * may belong to someone who registered it first, and factors they added
     * would survive the real owner's password reset.
     */
    protected function enrollable(Request $request, string $key): Enrollable
    {
        if (! $this->keyring->allowsEnrollment($this->keyring->user())) {
            EnrollmentRefused::dispatch($this->keyring->user(), $key, 'not_allowed');

            abort(403, __('keyring::keyring.verify_email_first'));
        }

        $factor = $this->keyring->factor($key);

        return $factor instanceof Enrollable ? $factor : abort(404);
    }
}
