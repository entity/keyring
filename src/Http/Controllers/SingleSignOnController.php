<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Closure;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Pipeline\Pipeline;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Enums\Purpose;
use Keyring\Enums\SsoFailure;
use Keyring\Events\EnrollmentRefused;
use Keyring\Events\FactorFailed;
use Keyring\Events\ProviderIdentityAccepted;
use Keyring\Exceptions\SsoFailed;
use Keyring\Factors\SingleSignOn;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Detours;
use Keyring\Login\SignIn;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Verifier;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\PendingAuthorizations;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Signing in with an identity provider, confirming a step-up with one, and
 * the callback it sends the user back to. One callback per provider serves
 * signing in, linking and confirming alike, so the provider has one
 * redirect URI to register. What the callback is for is in the request it
 * was started with, kept in the session, and that decides who may finish
 * it: a guest signs in, through the same pipeline as the login form, the
 * user who started a link finishes it, with what Keyring's routes for
 * adding a sign-in method ask, and the user who started a confirm finishes
 * it through the pipeline the confirm page's own factors go through.
 */
class SingleSignOnController
{
    use ChoosesFormat, RespondsWithStatus;

    // A route keeps its controller once it has made one, and in a worker
    // that serves many requests that can be longer than a request lasts.
    // These hold the session they were made for, so they're asked of the
    // app handling the request each time.
    protected PendingAuthorizations $pending { get => app(PendingAuthorizations::class); }

    protected EnrollmentStore $enrollments { get => app(EnrollmentStore::class); }

    protected SignIn $signIn { get => app(SignIn::class); }

    protected Detours $detours { get => app(Detours::class); }

    protected AttemptStore $attempts { get => app(AttemptStore::class); }

    protected Verifier $verifier { get => app(Verifier::class); }

    public function __construct(
        protected KeyringManager $keyring,
        protected AuthenticatorChanges $changes,
        protected Router $router,
    ) {}

    /**
     * Send a guest to the provider to sign in: a redirect, or the URL as
     * JSON for a frontend that goes there itself. "remember" is kept for
     * the callback.
     */
    public function redirect(Request $request, string $provider): Response
    {
        $factor = $this->factor($provider);

        try {
            $url = $this->keyring->sso()->start($provider, SingleSignOn::LOGIN, $factor->redirectUri($provider), [
                'remember' => $request->boolean('remember'),
            ]);
        } catch (SsoFailed $e) {
            $factor->report($e);

            return $this->failed($request, route('login'), [$factor->errorKey() => $factor->failure($provider)]);
        }

        return $this->away($request, $url);
    }

    /**
     * Send the user back to the provider of a link the confirm page offers,
     * to confirm the step-up by signing in there. A provider that
     * reauthenticates is asked for a new sign in there and then (max_age=0,
     * and prompt=login where it takes it). Any provider is told which
     * account to use (login_hint) where it takes that. The link is the one
     * "authenticator" names, the one the page showed, or the only one.
     * Answered as redirect() is.
     */
    public function reauthenticate(Request $request): Response
    {
        $factor = $this->registered();
        $attempt = $this->attempts->current(Purpose::Confirm);
        $back = route('keyring.confirm.challenge');

        if ($attempt === null || $attempt->exhausted) {
            return $this->failed($request, $back, [$factor->errorKey() => __('keyring::keyring.expired')]);
        }

        $options = $attempt->options()->where('factor', '===', $factor->key());
        $id = $request->query('authenticator') ?? $attempt->presented($factor->key());
        $authenticator = $options->firstWhere('id', '===', $id) ?? ($options->count() === 1 ? $options->first() : null);

        abort_if($authenticator === null, 404);

        $provider = (string) $authenticator->meta('provider');

        try {
            $url = $this->keyring->sso()->start($provider, SingleSignOn::CONFIRM, $factor->redirectUri($provider), [
                'user' => (string) $this->keyring->user()->getAuthIdentifier(),
                'attempt' => $attempt->id,
                'authenticator' => $authenticator->id,
            ], maxAge: $factor->reauthenticates($authenticator) ? 0 : null, loginHint: $this->loginHint($authenticator));
        } catch (SsoFailed $e) {
            $factor->report($e);

            return $this->failed($request, $back, [$factor->errorKey() => $factor->failure($provider)]);
        }

        return $this->away($request, $url);
    }

    /**
     * Where the provider sends the user back to. The request it names is
     * looked at, and only taken once the middleware for what it's for has
     * let the callback through: a link that needs the user to confirm it's
     * them first can still finish when they come back.
     */
    public function callback(Request $request, string $provider): Response
    {
        $factor = $this->factor($provider);
        $state = $request->query('state');
        $pending = is_string($state) && $state !== '' ? $this->pending->find($state) : null;

        // Only Keyring's own requests finish here. One an app started with
        // Keyring::sso() for something else is its own callback's to
        // finish, so it's spent, and this one isn't there for it.
        if ($pending !== null && ! in_array($pending->purpose, [SingleSignOn::LOGIN, SingleSignOn::LINK, SingleSignOn::CONFIRM], true)) {
            $this->pending->pull($pending->state);

            abort(404);
        }

        $guard = config('keyring.guard');

        // A state that isn't this browser's, or has expired, can never
        // finish. For someone signed in it fails straight away:
        // taken as a link, a fresh verification it needs would send them to
        // confirm and back to a callback that can never finish.
        if ($pending === null && $this->keyring->guard()->check()) {
            return $this->through($request, ['auth:'.$guard, 'throttle:keyring'], fn () => $this->unknown($request, $factor, $provider, is_string($state) ? $state : ''));
        }

        // A guest's callback can fail as often as it's sent, and each
        // failure is logged and dispatched, so it draws on the same limit
        // as the redirect that started it. A confirm needs no recent
        // verification: it's how the user gets one.
        return match ($pending->purpose ?? SingleSignOn::LOGIN) {
            SingleSignOn::LINK => $this->through($request, ['auth:'.$guard, ...Arr::wrap(config('keyring.changes_middleware')), 'throttle:keyring'], fn () => $this->link($request, $factor, $provider, $pending ?? throw new LogicException('Only a request started to link is for one.'))),
            SingleSignOn::CONFIRM => $this->through($request, ['auth:'.$guard, 'throttle:keyring'], fn () => $this->confirm($request, $factor, $provider, $pending ?? throw new LogicException('Only a request started to confirm is for one.'))),
            default => $this->through($request, ['guest:'.$guard, 'throttle:keyring-login-options'], fn () => $this->login($request, $factor, $provider, $pending)),
        };
    }

    /**
     * A callback this browser has no live request for, while someone is
     * signed in. One that expired says what it was for, and goes back to
     * where it would have: a confirm to the confirm page, which starts
     * one again, and a link to the page it was started from. Nothing is
     * known of one used already, or someone else's. With a confirm in
     * progress it was most likely that, so it goes back to the confirm
     * page, and otherwise home.
     */
    protected function unknown(Request $request, SingleSignOn $factor, string $provider, string $state): Response
    {
        $expired = $state === '' ? null : $this->pending->pullExpired($state);
        $confirm = route('keyring.confirm.challenge');

        return match (true) {
            $expired?->purpose === SingleSignOn::CONFIRM => $this->failed($request, $confirm, [$factor->errorKey() => __('keyring::keyring.expired')]),
            $expired?->purpose === SingleSignOn::LINK => $this->failed($request, $this->returnTo($expired), ['provider' => __('keyring::keyring.enrollment_expired')]),
            $expired === null && $this->attempts->current(Purpose::Confirm) !== null => $this->failed($request, $confirm, [$factor->errorKey() => __('keyring::keyring.expired')]),
            default => $this->failed($request, $this->returnTo(null), ['provider' => $factor->failure($provider)]),
        };
    }

    /**
     * Sign in whoever linked the account the provider vouched for, as the
     * login form would, and answer as it does. Failures go to the login
     * page, which the user came from.
     */
    protected function login(Request $request, SingleSignOn $factor, string $provider, ?AuthorizationRequest $pending): Response
    {
        // Only a sign in signs anyone in. A state this browser doesn't have
        // fails at complete(), as it always would.
        abort_unless($pending === null || $pending->purpose === SingleSignOn::LOGIN, 404);

        try {
            $identity = $this->keyring->sso()->complete($request, $provider);
        } catch (SsoFailed $e) {
            if ($e->reason === SsoFailure::Denied) {
                return $this->status('sso-cancelled', redirect: route('login'))->toResponse($request);
            }

            $factor->report($e);
            FactorFailed::dispatch(null, null, $factor->key(), $request);

            return $this->failed($request, route('login'), [$factor->errorKey() => $factor->failure($provider)]);
        }

        $request->attributes->set(SingleSignOn::IDENTITY, $identity);
        $request->merge(['remember' => (bool) ($identity->request->data['remember'] ?? false)]);

        try {
            return $this->keyring->attempt($request, $factor->key());
        } catch (ValidationException $e) {
            // A failed form post goes back to the form. This came from the
            // provider, so it goes to the login page instead.
            return $this->failed($request, route('login'), $e->errors(), $e);
        }
    }

    /**
     * Confirm the step-up the request was started for with the link it was
     * started with, through the pipeline the confirm page's factors go
     * through, so rate limits, events and the confirm's requirement apply
     * as they do there. Done, it goes on to the page the confirm was for,
     * and otherwise back to the confirm page.
     */
    protected function confirm(Request $request, SingleSignOn $factor, string $provider, AuthorizationRequest $pending): Response
    {
        $back = route('keyring.confirm.challenge');
        $attempt = $this->attempts->current(Purpose::Confirm);
        $authenticator = $this->confirming($attempt, $pending);

        // Someone else signed in on this browser since it was started, or
        // the confirm it was for is over: finished, expired, or replaced
        // by one asking for something else.
        if ($attempt === null || $authenticator === null || ! $factor->startedBy($pending, $this->keyring->user())) {
            $this->pending->pull($pending->state);

            return $this->failed($request, $back, [$factor->errorKey() => __('keyring::keyring.expired')]);
        }

        try {
            $identity = $this->keyring->sso()->complete($request, $provider);
        } catch (SsoFailed $e) {
            if ($e->reason === SsoFailure::Denied) {
                return $this->status('sso-cancelled', redirect: $back)->toResponse($request);
            }

            $factor->report($e);
            FactorFailed::dispatch($attempt, $authenticator, $factor->key(), $request);

            return $this->failed($request, $back, [$factor->errorKey() => $factor->failure($provider)]);
        }

        $request->attributes->set(SingleSignOn::IDENTITY, $identity);

        try {
            // Out of guesses, nothing can finish this attempt. Failing it
            // here keeps the account's counters counting, as the confirm
            // page's own verify does.
            return $this->verifier->respond(new Context($request, Purpose::Confirm, $factor, $attempt, $attempt->exhausted ? null : $authenticator));
        } catch (ValidationException $e) {
            return $this->failed($request, $back, $e->errors(), $e);
        }
    }

    /**
     * The address the provider had for the link last time, for it to pick
     * the account to sign in with.
     */
    protected function loginHint(Authenticator $authenticator): ?string
    {
        $email = $authenticator->meta('email');

        return is_string($email) && $email !== '' ? $email : null;
    }

    /**
     * The link a confirm was started with, while the attempt it was
     * started for is the one in progress and still offers it.
     */
    protected function confirming(?Attempt $attempt, AuthorizationRequest $pending): ?Authenticator
    {
        if ($attempt === null || $attempt->id !== ($pending->data['attempt'] ?? null)) {
            return null;
        }

        return $attempt->options()->first(fn (Authenticator $option) => $option->id === ($pending->data['authenticator'] ?? null));
    }

    /**
     * Link the account the provider vouched for to the user who started
     * the link. The same account linked to anyone else is refused without
     * saying who, and one already linked to them is only brought up to
     * date.
     */
    protected function link(Request $request, SingleSignOn $factor, string $provider, AuthorizationRequest $pending): Response
    {
        $user = $this->keyring->user();
        $return = $this->returnTo($pending);

        if (! $this->keyring->allowsEnrollment($user)) {
            EnrollmentRefused::dispatch($user, $factor->key(), 'not_allowed');

            abort(403, __('keyring::keyring.verify_email_first'));
        }

        $refuse = function () use ($request, $user, $factor, $provider, $return) {
            EnrollmentRefused::dispatch($user, $factor->key(), 'invalid');

            return $this->failed($request, $return, ['provider' => $factor->failure($provider, 'sso_link_failed')]);
        };

        // Someone else signed in on this browser since it was started.
        if (! $factor->startedBy($pending, $user)) {
            $this->pending->pull($pending->state);

            return $refuse();
        }

        try {
            $identity = $this->keyring->sso()->complete($request, $provider);
        } catch (SsoFailed $e) {
            if ($e->reason === SsoFailure::Denied) {
                return $this->status('sso-cancelled', redirect: $return)->toResponse($request);
            }

            $factor->report($e);

            return $refuse();
        }

        $enrollment = $this->enrollments->get($factor->key());

        if ($enrollment === null || $enrollment->id !== ($identity->request->data['enrollment'] ?? null)) {
            return $this->failed($request, $return, ['provider' => __('keyring::keyring.enrollment_expired')]);
        }

        $linked = $factor->linked($identity);

        if ($linked !== null && ! $linked->authenticatable?->is($user)) {
            return $refuse();
        }

        if ($linked !== null) {
            $factor->bringUpToDate($linked, $identity)->save();
            $this->enrollments->forget($factor->key());
            ProviderIdentityAccepted::dispatch($user, $linked, $identity, SingleSignOn::LINK);

            return $this->status('authenticator-updated', ['authenticator' => $factor->present($linked)], $return)->toResponse($request);
        }

        $request->attributes->set(SingleSignOn::IDENTITY, $identity);
        $authenticator = $factor->confirmEnrollment($user, $enrollment, $request) ?? throw new LogicException('The callback has the identity the enrollment was started for.');

        // Each enrollment adds its authenticator once. The callback's state
        // was already claimed, so only two callbacks of one link racing
        // each other get here twice.
        if (! $this->enrollments->claim($enrollment)) {
            return $this->failed($request, $return, ['provider' => __('keyring::keyring.enrollment_expired')]); // @codeCoverageIgnore
        }

        try {
            $this->changes->add($user, $factor, $authenticator, $request);
            // @codeCoverageIgnoreStart
        } catch (UniqueConstraintViolationException) {
            // Only when two links of the same account race each other: the
            // other one was saved first.
            return $refuse();
        }
        // @codeCoverageIgnoreEnd

        $this->enrollments->forget($factor->key());
        $this->signIn->enrolled($request, $authenticator, $factor->provedBy($authenticator, $identity));
        ProviderIdentityAccepted::dispatch($user, $authenticator, $identity, SingleSignOn::LINK);

        return $this->status('authenticator-added', array_filter([
            'authenticator' => $factor->present($authenticator),
            'continue' => $this->detours->pull($request, Detours::ENROLLMENT),
        ]), $return)->toResponse($request);
    }

    /**
     * The factor, when it's registered and the provider is configured.
     * Otherwise these routes aren't there.
     */
    protected function factor(string $provider): SingleSignOn
    {
        $factor = $this->registered();

        // A 404 for one that isn't configured.
        $this->keyring->sso()->provider($provider);

        return $factor;
    }

    /**
     * The factor, when it's registered. Otherwise these routes aren't there.
     */
    protected function registered(): SingleSignOn
    {
        $factor = $this->keyring->hasFactor(SingleSignOn::KEY) ? $this->keyring->factor(SingleSignOn::KEY) : null;

        abort_unless($factor instanceof SingleSignOn, 404);

        return $factor;
    }

    /**
     * Off to the provider: a redirect, the URL as JSON for a frontend that
     * goes there itself, or for an Inertia visit, a full page load.
     */
    protected function away(Request $request, string $url): Response
    {
        return match (true) {
            $this->wantsJson($request) => new JsonResponse(['url' => $url]),
            $request->hasHeader('X-Inertia') => $this->loadInFull($url),
            default => redirect()->away($url),
        };
    }

    /**
     * Run the callback through the middleware a route for its purpose
     * would have, then the action.
     *
     * @param  array<mixed>  $middleware  names or classes, as a route takes them
     * @param  Closure(): Response  $action
     */
    protected function through(Request $request, array $middleware, Closure $action): Response
    {
        return new Pipeline(app())
            ->send($request)
            ->through($this->router->resolveMiddleware($middleware))
            ->then(fn () => $action());
    }

    /**
     * Back to the page a link was started from, which was checked to be
     * this site's when it was.
     */
    protected function returnTo(?AuthorizationRequest $pending): string
    {
        $return = $pending?->data['return'] ?? null;

        return is_string($return) ? $return : url()->to(config('keyring.home'));
    }

    /**
     * A failure: the errors for a JSON request, as any form's, and for a
     * browser on its way back from the provider, a redirect with them.
     *
     * @param  array<string, string|list<string>>  $errors
     */
    protected function failed(Request $request, string $to, array $errors, ?ValidationException $thrown = null): Response
    {
        if ($this->wantsJson($request)) {
            throw $thrown ?? ValidationException::withMessages($errors);
        }

        return redirect($to)->withErrors($errors);
    }
}
