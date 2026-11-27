<?php

declare(strict_types=1);

namespace Keyring;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Everything a user can sign in with, across every registered factor.
 */
class UserKeyring
{
    /** @var Collection<int, Authenticator>|null */
    protected ?Collection $authenticators = null;

    /** @var Collection<int, Authenticator>|null */
    protected ?Collection $stored = null;

    public function __construct(
        public readonly Authenticatable&Model $user,
        protected KeyringManager $keyring,
    ) {}

    /**
     * The keys of factors the user has authenticators for that aren't
     * registered. Keyring can't check those, so it won't sign the user in
     * without them.
     *
     * @return list<string>
     */
    public function unregistered(): array
    {
        return array_values($this->stored()
            ->map(fn (Authenticator $authenticator) => $authenticator->factor)
            ->unique()
            ->reject(fn (string $factor) => $this->keyring->hasFactor($factor))
            ->all());
    }

    /**
     * @return Collection<int, Authenticator>
     */
    protected function stored(): Collection
    {
        return $this->stored ??= $this->keyring->authenticatorModel()::query()
            ->ownedBy($this->user)
            ->confirmed()
            ->get()
            ->each(fn (Authenticator $authenticator) => $authenticator->setRelation('authenticatable', $this->user));
    }

    /**
     * Every confirmed authenticator, defaults first, then by factor priority.
     *
     * @return Collection<int, Authenticator>
     */
    public function all(): Collection
    {
        return $this->authenticators ??= $this->load();
    }

    /**
     * The authenticator offered first for an extra factor.
     */
    public function default(): ?Authenticator
    {
        return $this->all()->firstWhere('is_default', true)
            ?? $this->all()->first(fn (Authenticator $authenticator) => ! $authenticator->isVirtual() && $this->answers($authenticator));
    }

    /**
     * Whether a challenge or a step-up could ask for it: anything but a
     * factor whose proof is who it identified, like an identity provider.
     * A step-up ($purpose Confirm) can still send the user back to the
     * provider of a single sign-on link (SingleSignOn::confirms()).
     */
    public function answers(Authenticator $authenticator, ?Purpose $purpose = null): bool
    {
        $factor = $authenticator->factor();

        return ! $factor instanceof PrimaryFactor
            || $factor->answersChallenges()
            || ($purpose === Purpose::Confirm && $factor instanceof SingleSignOn && $factor->confirms($authenticator));
    }

    /**
     * @return Collection<int, Authenticator>
     */
    public function of(string $factor): Collection
    {
        return $this->all()->where('factor', '===', $factor)->values();
    }

    public function find(?string $id): ?Authenticator
    {
        return $id === null ? null : $this->all()->first(fn (Authenticator $authenticator) => $authenticator->id === $id);
    }

    public function has(Category $category): bool
    {
        return $this->all()->contains(
            fn (Authenticator $authenticator) => in_array($category, $authenticator->factor()->categories($authenticator), true),
        );
    }

    /**
     * Whether the user has a real second factor. A password used with one
     * may be shorter. Recovery codes aren't one to rely on, and an emailed
     * code isn't a factor at all (Category::Address).
     */
    public function hasSecondFactor(): bool
    {
        return $this->withoutFallbacks()->canMeet(Requirement::aal2());
    }

    /**
     * Whether the user has a factor recovery codes can stand in for: anything
     * stored that is one, besides the codes themselves. An emailed code
     * isn't: the inbox it goes to is how the account is recovered anyway.
     * Nor is a linked identity provider, which is never asked for as a
     * second step.
     */
    public function hasFactorToRecover(): bool
    {
        return $this->all()->contains(fn (Authenticator $authenticator) => ! $authenticator->isVirtual()
            && $authenticator->factor !== RecoveryCodes::KEY
            && $this->answers($authenticator)
            && array_any($authenticator->factor()->categories($authenticator), fn (Category $category) => $category->authenticates()));
    }

    /**
     * Whether the user has any recovery codes left.
     */
    public function hasRecoveryCodes(): bool
    {
        return $this->of(RecoveryCodes::KEY)->contains(fn (Authenticator $set) => $set->factor()->categories($set) !== []);
    }

    /**
     * Whether a recovery code has been used since the set was made. NIST
     * SP 800-63B-4 (Sec. 4.2.1.1) has a used code replaced with a new one.
     * Only the user can save new codes, so this is for the app to send them
     * to make a new set, and stays true until they have.
     */
    public function shouldReplaceRecoveryCodes(): bool
    {
        return $this->of(RecoveryCodes::KEY)->contains(fn (Authenticator $set) => $set->meta(RecoveryCodes::USED_AT) !== null);
    }

    /**
     * The keyring without recovery codes: a way back in, not a factor to
     * rely on.
     */
    public function withoutFallbacks(): static
    {
        return $this->without(...$this->of(RecoveryCodes::KEY)->all());
    }

    /**
     * Whether the user's authenticators could, together, meet the requirement.
     */
    public function canMeet(Requirement $requirement): bool
    {
        return $requirement->isMetBy($this->provable());
    }

    /**
     * The requirement as far as the user's authenticators can meet it: all
     * of it when they can, else the strongest version they can give.
     * Recovery codes aren't counted on, or a user with nothing else beyond
     * one factor would spend a code every time.
     */
    public function reachable(Requirement $requirement): Requirement
    {
        $provable = $this->withoutFallbacks()->provable();

        return $requirement->isMetBy($provable) ? $requirement : $requirement->limitedTo($provable);
    }

    /**
     * Whether a confirm could meet the requirement: what the session
     * already proved, built on as the confirm does, with everything the
     * confirm page can ask for (answers()). Without that, the user would
     * prove what they can and still be stuck.
     *
     * @param  list<Verification>  $proved
     */
    public function canConfirm(Requirement $requirement, array $proved = []): bool
    {
        return $requirement->isMetBy([...$proved, ...$this->askable(Purpose::Confirm)]);
    }

    /**
     * What the page for $purpose could add: what each authenticator it
     * can ask for (answers()) would prove (wouldProve()). canConfirm() and
     * codeCouldFinish() both go by it, and Detours through canConfirm(),
     * so what they say a confirm can give is what the page offers.
     *
     * @return list<Verification>
     */
    protected function askable(?Purpose $purpose): array
    {
        return array_values($this->all()
            ->filter(fn (Authenticator $authenticator) => $this->answers($authenticator, $purpose))
            ->map($this->wouldProve(...))
            ->all());
    }

    /**
     * The keyring without what can never count toward a fresh verification
     * (Requirement::freshlyProved()): a single sign-on link whose sign ins
     * are never fresh, like GitHub's by default.
     */
    public function freshlyProvable(): static
    {
        return $this->without(...$this->all()
            ->filter(fn (Authenticator $authenticator) => $this->wouldProve($authenticator)->authenticatedAt === Verification::UNKNOWN)
            ->all());
    }

    /**
     * What each authenticator would prove, if the user verified them all.
     *
     * @return list<Verification>
     */
    protected function provable(): array
    {
        return array_values($this->all()->map($this->wouldProve(...))->all());
    }

    /**
     * What verifying the authenticator would prove: as its factor says
     * now, except that a single sign-on link knows whether it can ever
     * count as recent (SingleSignOn::wouldProve()).
     */
    protected function wouldProve(Authenticator $authenticator): Verification
    {
        $factor = $authenticator->factor();

        return $factor instanceof SingleSignOn ? $factor->wouldProve($authenticator) : Verification::of($authenticator);
    }

    /**
     * Authenticators that would bring the verifications closer to the
     * requirement. These are what a challenge or a step-up offers, so a
     * factor that can only start a login isn't among them, except a single
     * sign-on link on a step-up ($purpose Confirm), as answers() says, and
     * only where what it proves counts: never toward a fresh verification
     * when its sign ins are never fresh.
     *
     * @param  list<Verification>  $verifications
     * @return Collection<int, Authenticator>
     */
    public function usefulFor(Requirement $requirement, array $verifications, ?Purpose $purpose = null): Collection
    {
        $used = array_filter(array_map(fn (Verification $verification) => $verification->authenticator ?? $verification->factor, $verifications));

        return $this->all()
            ->reject(fn (Authenticator $authenticator) => in_array($authenticator->id, $used, true))
            ->filter(fn (Authenticator $authenticator) => $this->answers($authenticator, $purpose))
            ->filter(fn (Authenticator $authenticator) => $requirement->wouldProgress($verifications, $this->wouldProve($authenticator)))
            ->reject(fn (Authenticator $authenticator) => $authenticator->factor === RecoveryCodes::KEY && ! $this->codeCouldFinish($requirement, $verifications, $authenticator, $purpose))
            ->values();
    }

    /**
     * Whether spending a recovery code could finish the attempt. A code
     * stands in for a lost possession factor, so what's left must not need
     * another one, or it would be spent and the user still stuck. What's
     * left is what the page could still ask for (askable()), as it would
     * prove it: a link whose sign ins are never fresh finishes nothing
     * fresh. A requirement that refuses codes can't be finished by one at
     * all.
     *
     * @param  list<Verification>  $verifications
     */
    protected function codeCouldFinish(Requirement $requirement, array $verifications, Authenticator $set, ?Purpose $purpose): bool
    {
        $rest = array_filter($this->askable($purpose), fn (Verification $other) => ! in_array(Category::Possession, $other->categories, true));

        return $requirement->acceptsRecoveryCodes && $requirement->isMetBy([...$verifications, Verification::of($set), ...$rest]);
    }

    /**
     * The keyring as it would be without the given authenticators.
     */
    public function without(Authenticator ...$authenticators): static
    {
        $ids = array_map(fn (Authenticator $authenticator) => $authenticator->id, $authenticators);

        $keyring = clone $this;
        $keyring->authenticators = $this->all()->reject(fn (Authenticator $other) => in_array($other->id, $ids, true))->values();

        return $keyring;
    }

    /**
     * Whether any authenticator can start a login on its own.
     */
    public function canSignIn(): bool
    {
        return $this->all()->contains(function (Authenticator $authenticator) {
            $factor = $authenticator->factor();

            return $factor instanceof PrimaryFactor && $factor->startsLogin();
        });
    }

    public function refresh(): static
    {
        $this->authenticators = null;
        $this->stored = null;

        return $this;
    }

    /**
     * @return Collection<int, Authenticator>
     */
    protected function load(): Collection
    {
        return $this->keyring->registered()
            ->flatMap(fn (Factor $factor) => $factor->authenticators($this->user, $this->stored()))
            ->sortBy([
                fn (Authenticator $a, Authenticator $b) => $b->is_default <=> $a->is_default,
                fn (Authenticator $a, Authenticator $b) => $b->factor()->priority() <=> $a->factor()->priority(),
                fn (Authenticator $a, Authenticator $b) => $a->created_at <=> $b->created_at,
            ])
            ->values();
    }
}
