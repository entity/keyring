<?php

declare(strict_types=1);

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\IdentityProvider;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Enums\SsoFreshness;
use Keyring\Events\ProviderIdentityAccepted;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Support\Input;
use Keyring\Support\Url;
use Throwable;

/**
 * Signing in with an identity provider from keyring.sso.providers: "Sign
 * in with Google". Each account at a provider the user links is one of
 * their authenticators, matched on the provider's issuer and subject and
 * never on the email address, which some providers let an account carry
 * unproven.
 *
 * The proof is who the provider vouched for, so it starts a sign in, and
 * is never asked for as a second step. It goes through the same pipeline
 * as the login form, so rate limits, the policy and risk all apply, and a
 * user with a second factor is still asked for it. It stands in for the
 * password, so it counts as the same kind of proof.
 *
 * A link also confirms a step-up: the confirm page sends the user back to
 * its provider, and the callback has to bring the same account for the
 * user who started it.
 *
 * How a sign in or a confirm counts toward a fresh verification is the
 * provider's freshness() (SsoFreshness). With Reauthenticate, it's asked
 * for auth_time with every sign in where it takes the claims parameter,
 * and the auth_time it sends is when a sign in counts as proved for
 * freshness, so being let straight through on an old session there isn't a
 * recent verification, nor is a sign in it didn't say the time of. A
 * confirm asks it for a new sign in (max_age=0, and prompt=login where it
 * takes one), and has to come back with an auth_time from after the user
 * was sent there. With RoundTrip, which a provider only has when the
 * config says so, a sign in or a confirm counts as proved when it comes
 * back, however old the user's session there is. With Never, the default
 * for GitHub, Google and any plain OAuth 2.0 driver, a sign in never
 * counts as recent, and nor does a confirm, which is a plain round trip.
 * That still counts toward the session's level, as signing in through it
 * again would, so the confirm page offers the link toward a level, such as
 * AAL2 once it has lapsed, and never toward a fresh verification, which
 * needs another method.
 *
 * Linking is an enrollment: POST /user/authenticators/sso with a "provider"
 * begins it and answers with the URL to send the user to, and the
 * provider's callback confirms it. Nobody is signed up or linked by their
 * email address: an account at a provider has to be linked by its owner,
 * signed in here, before it signs anyone in.
 */
class SingleSignOn extends Factor implements Enrollable, PrimaryFactor
{
    use ChoosesFormat;

    public const string KEY = 'sso';

    /**
     * What a sign in through a provider is for.
     */
    public const string LOGIN = 'login';

    public const string LINK = 'link';

    public const string CONFIRM = 'confirm';

    /**
     * The request attribute the callback puts the provider's identity in,
     * for identify() and confirmEnrollment() to read.
     */
    public const string IDENTITY = 'keyring.sso.identity';

    /**
     * How much of a provider's "amr" and "acr" a verification keeps: the
     * first AMR_VALUES distinct amr values that match AMR_VALUE, and an acr
     * that matches ACR_VALUE, printable ASCII up to 255 characters.
     * Anything else is left out, so a provider can't fill the session with
     * what it sends.
     */
    public const int AMR_VALUES = 10;

    public const string AMR_VALUE = '/^[A-Za-z0-9._:\/-]{1,64}$/D';

    public const string ACR_VALUE = '/^[\x21-\x7E]{1,255}$/D';

    public function key(): string
    {
        return self::KEY;
    }

    public function startsLogin(): bool
    {
        return true;
    }

    /**
     * The provider's answer only comes with its callback, so this is never
     * offered as a second step, nor given recovery codes or made the
     * default. A step-up can still ask for a link that confirms().
     */
    public function answersChallenges(): bool
    {
        return false;
    }

    /**
     * Whether the confirm page can offer the link: its provider is
     * configured and can be built, and the route that sends the user there
     * is registered. One whose freshness() is Never is only offered where
     * it can help (wouldProve()): toward a level, never toward a fresh
     * verification.
     */
    public function confirms(Authenticator $authenticator): bool
    {
        return Route::has('keyring.sso.confirm') && $this->freshnessOf($authenticator->meta('provider')) !== null;
    }

    /**
     * What confirming with the link proves: a verification now, or with
     * a provider whose freshness() is Never, one at Verification::UNKNOWN,
     * which counts toward the session's level as signing in through it
     * again would, and never toward a fresh verification. So is a link
     * whose provider isn't configured, or can't be built.
     */
    public function wouldProve(Authenticator $authenticator): Verification
    {
        return in_array($this->freshnessOf($authenticator->meta('provider')), [null, SsoFreshness::Never], true)
            ? Verification::of($authenticator, authenticatedAt: Verification::UNKNOWN)
            : Verification::of($authenticator);
    }

    /**
     * Whether a confirm with the link asks its provider for a new sign in:
     * its freshness() is Reauthenticate. One that isn't configured, or
     * can't be built, can't be asked.
     */
    public function reauthenticates(Authenticator $authenticator): bool
    {
        return $this->freshnessOf($authenticator->meta('provider')) === SsoFreshness::Reauthenticate;
    }

    /**
     * What a sign in or a confirm with the link counts for: the strictest
     * of the freshness of the provider the identity came through and of
     * the one the link was made with (SsoFreshness::strictest()), each as
     * Sso::freshness() resolves it. A provider that was renamed or removed
     * in the config loosens nothing: it can't make a sign in count for more
     * than the provider it came through says, and with neither known,
     * nothing counts.
     */
    public function freshness(Authenticator $authenticator, Identity $identity): SsoFreshness
    {
        return SsoFreshness::strictest($this->freshnessOf($identity->provider), $this->freshnessOf($authenticator->meta('provider')));
    }

    /**
     * The freshness of the provider configured under the name, or null
     * when there's none or it can't be built.
     */
    protected function freshnessOf(mixed $provider): ?SsoFreshness
    {
        try {
            return is_string($provider) && Keyring::sso()->has($provider) ? Keyring::sso()->freshness($provider) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * On the confirm page: the provider, and the URL that sends the user
     * there to sign in again. Showing the page starts nothing, so it can
     * be shown as often as it's asked for.
     */
    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        $provider = (string) $authenticator->meta('provider');

        return [
            'provider' => $provider,
            'label' => Keyring::sso()->provider($provider)->label(),
            'url' => route('keyring.sso.confirm', ['authenticator' => $authenticator->id]),
        ];
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Knowledge];
    }

    public function priority(): int
    {
        return 30;
    }

    /**
     * Who the provider's callback is for: the user who linked the account
     * it vouched for. One nobody linked signs nobody in, and is answered
     * like a wrong password.
     */
    public function identify(Request $request): ?Authenticator
    {
        $identity = $request->attributes->get(self::IDENTITY);

        return $identity instanceof Identity ? $this->linked($identity) : null;
    }

    /**
     * Only called on the callback: to sign in, straight after identify()
     * found the user the provider vouched for, and to confirm, with the
     * link the confirm was started for. Either way the provider has to
     * have vouched for that link's account, and a confirm has to be the one
     * started for this user and this link (confirmedBy()). The address the
     * provider has for them is kept as it was last seen.
     *
     * A sign in is proved as provedBy() says, and a confirm now, since one
     * that reauthenticates came back with a new sign in, except where the
     * link's freshness() is Never: that round trip counts toward the level
     * alone, at Verification::UNKNOWN, as wouldProve() said it would. When the provider the link
     * was made with is no longer configured, the one the identity came
     * through is kept on the link instead, so a link whose key was renamed
     * in the config is offered on the confirm page again. Otherwise the
     * link keeps its own, so the stricter of the two goes on counting
     * however many sign ins come through the other.
     *
     * Accepted, it dispatches ProviderIdentityAccepted with the identity,
     * before the rest of the pipeline has run: a second factor may still
     * be asked for.
     */
    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $identity = $request->attributes->get(self::IDENTITY);

        if (! $identity instanceof Identity || $authenticator->credential_id !== self::credentialId($identity->issuer, $identity->subject)) {
            return null;
        }

        if ($attempt->purpose === Purpose::Confirm && ! $this->confirmedBy($identity, $attempt, $authenticator)) {
            return null;
        }

        $proved = match (true) {
            $attempt->purpose !== Purpose::Confirm => $this->provedBy($authenticator, $identity),
            $this->freshness($authenticator, $identity) === SsoFreshness::Never => $this->proved($authenticator, $identity, Verification::UNKNOWN),
            default => $this->proved($authenticator, $identity),
        };

        $this->bringUpToDate($authenticator, $identity);

        ProviderIdentityAccepted::dispatch($attempt->user(), $authenticator, $identity, $attempt->purpose === Purpose::Confirm ? self::CONFIRM : self::LOGIN);

        return $proved;
    }

    /**
     * The link with what the provider just said about it, not yet saved:
     * the address it has now, and the provider the identity came through
     * when the one the link was made with is no longer configured. A link
     * keeps its own provider otherwise, so a stricter one goes on counting
     * however many sign ins or links come through another on the same
     * issuer.
     */
    public function bringUpToDate(Authenticator $authenticator, Identity $identity): Authenticator
    {
        $authenticator->withMeta('email', $identity->email);

        if (! Keyring::sso()->has((string) $authenticator->meta('provider'))) {
            $authenticator->withMeta('provider', $identity->provider);
        }

        return $authenticator;
    }

    /**
     * The verification of the link a sign in or a new link brings, as its
     * freshness() says: with Reauthenticate, proved when the provider says
     * the user signed in there, and with no auth_time at
     * Verification::UNKNOWN, with Never at Verification::UNKNOWN whatever
     * it says, so it never counts as recent, and with RoundTrip now. It
     * keeps the provider's amr and acr (proved()).
     */
    public function provedBy(Authenticator $authenticator, Identity $identity): Verification
    {
        return match ($this->freshness($authenticator, $identity)) {
            SsoFreshness::Reauthenticate => $this->proved($authenticator, $identity, $identity->authTime ?? Verification::UNKNOWN),
            SsoFreshness::Never => $this->proved($authenticator, $identity, Verification::UNKNOWN),
            SsoFreshness::RoundTrip => $this->proved($authenticator, $identity),
        };
    }

    /**
     * A verification of the link now, proved at $authenticatedAt if
     * that's earlier, with what the provider said of how the user signed
     * in there: its amr and acr, as far as they're kept (AMR_VALUES,
     * AMR_VALUE, ACR_VALUE). They're the provider's say, and count toward
     * nothing: what the link proves is the same whatever they are.
     */
    protected function proved(Authenticator $authenticator, Identity $identity, ?int $authenticatedAt = null): Verification
    {
        // A custom driver may hand over anything in a claim, whatever Identity's docblock says.
        $amr = array_values(array_unique(array_filter($identity->amr, fn (mixed $value) => is_string($value) && preg_match(self::AMR_VALUE, $value) === 1))); // @phpstan-ignore function.alreadyNarrowedType
        $acr = $identity->acr !== null && preg_match(self::ACR_VALUE, $identity->acr) === 1 ? $identity->acr : null;

        return Verification::of($authenticator, authenticatedAt: $authenticatedAt, providerAmr: array_slice($amr, 0, self::AMR_VALUES), providerAcr: $acr);
    }

    /**
     * Whether the identity confirms the step-up: it came back from a
     * confirm started for this attempt's user, with this link, and when its
     * freshness() is Reauthenticate, from a request for a new sign in,
     * which Sso::complete() has already held to its auth_time. Otherwise a
     * round trip does, which is all signing in through the provider again
     * would take. What it proves is wouldProve()'s to say.
     */
    protected function confirmedBy(Identity $identity, Attempt $attempt, Authenticator $authenticator): bool
    {
        $request = $identity->request;

        return $request->purpose === self::CONFIRM
            && ($request->data['user'] ?? null) === (string) $attempt->userId
            && ($request->data['authenticator'] ?? null) === $authenticator->id
            && ($this->freshness($authenticator, $identity) !== SsoFreshness::Reauthenticate || $request->maxAge === 0);
    }

    public function identificationRules(): array
    {
        return [];
    }

    public function rules(): array
    {
        return [];
    }

    /**
     * The login page shows problems on its username field.
     */
    public function errorKey(): string
    {
        return Keyring::username();
    }

    /**
     * With the provider and the address it had for the account last time.
     */
    public function present(Authenticator $authenticator): array
    {
        return [
            ...parent::present($authenticator),
            'provider' => $authenticator->meta('provider'),
            'email' => $authenticator->meta('email'),
        ];
    }

    /**
     * Send the user to the provider they chose, to link the account they
     * sign in with there. The enrollment's props hold the URL to send them
     * to, and the callback confirms it. The page they started from is
     * where the callback sends them back to.
     *
     * @throws ValidationException
     */
    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        // Configured after the routes were registered, there's no callback
        // for the provider to send the user back to.
        Input::validate($request, ['provider' => ['required', 'string', Rule::in(Route::has('keyring.sso.callback') ? Keyring::sso()->names() : [])]]);

        $provider = Input::text($request, 'provider');
        $enrollment = Enrollment::make($this->key(), state: ['provider' => $provider]);

        try {
            $url = Keyring::sso()->start($provider, self::LINK, $this->redirectUri($provider), [
                'user' => (string) $user->getAuthIdentifier(),
                'enrollment' => $enrollment->id,
                'return' => $this->intendedUrl($request),
            ]);
        } catch (SsoFailed $e) {
            $this->report($e);

            throw ValidationException::withMessages(['provider' => $this->failure($provider)]);
        }

        return new Enrollment($enrollment->factor, ['provider' => $provider, 'url' => $url], $enrollment->state, $enrollment->expiresAt, $enrollment->id);
    }

    /**
     * The account the provider's callback vouched for, as a new
     * authenticator. Null without one: the confirm route has no callback to
     * read, so linking only ever finishes there.
     */
    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        $identity = $request->attributes->get(self::IDENTITY);

        if (! $identity instanceof Identity || $identity->provider !== $enrollment->state('provider')) {
            return null;
        }

        $label = Keyring::sso()->provider($identity->provider)->label();

        return $this->makeAuthenticator([
            'name' => str($identity->email === null ? $label : "{$label} ({$identity->email})")->limit(64, '')->value(),
            'credential_id' => self::credentialId($identity->issuer, $identity->subject),
            'meta' => [
                'provider' => $identity->provider,
                'issuer' => $identity->issuer,
                'subject' => $identity->subject,
                'email' => $identity->email,
            ],
        ]);
    }

    /**
     * The authenticator an account at a provider is linked as, whoever it
     * belongs to, or null when nobody has linked it.
     */
    public function linked(Identity $identity): ?Authenticator
    {
        return Keyring::authenticatorModel()::query()
            ->where('factor', $this->key())
            ->where('credential_id', self::credentialId($identity->issuer, $identity->subject))
            ->confirmed()
            ->first();
    }

    /**
     * What names the account at the provider among every authenticator's
     * credential ID: its issuer and subject, hashed to a fixed length that
     * no WebAuthn credential ID takes.
     */
    public static function credentialId(string $issuer, string $subject): string
    {
        return self::KEY.':'.hash('sha256', $issuer."\0".$subject);
    }

    /**
     * Whether the link was started by this user, who is still the one
     * signed in.
     */
    public function startedBy(AuthorizationRequest $request, Authenticatable $user): bool
    {
        return ($request->data['user'] ?? null) === (string) $user->getAuthIdentifier();
    }

    /**
     * The providers to offer, in the config's order: each one's name, what
     * its button says, and where the button sends a user to sign in.
     *
     * @return list<array{name: string, label: string, url: string}>
     */
    public function providers(): array
    {
        // Configured after the routes were registered, there's nowhere to
        // send anyone.
        if (! Route::has('keyring.sso.redirect')) {
            return [];
        }

        return Keyring::sso()->providers()
            ->map(fn (IdentityProvider $provider) => [
                'name' => $provider->name(),
                'label' => $provider->label(),
                'url' => route('keyring.sso.redirect', $provider->name()),
            ])
            ->values()
            ->all();
    }

    /**
     * Where a provider sends the user back to, for signing in, linking and
     * confirming alike, so each provider has the one URL to register. It starts where
     * emailed links do, so a frontend Laravel doesn't serve can take the
     * callback at the same path and pass it on.
     */
    public function redirectUri(string $provider): string
    {
        return Url::route('keyring.sso.callback', ['provider' => $provider]);
    }

    /**
     * Report a failure that was caught, unless it's one users bring about
     * every day (SsoFailed::expected()), so the app's logs say why a
     * provider keeps failing.
     */
    public function report(SsoFailed $e): void
    {
        report_unless($e->expected(), $e);
    }

    /**
     * The message for a sign in or link with a provider that didn't work.
     */
    public function failure(string $provider, string $key = 'sso_failed'): string
    {
        return (string) __('keyring::keyring.'.$key, ['provider' => Keyring::sso()->provider($provider)->label()]);
    }
}
