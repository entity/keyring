<?php

declare(strict_types=1);

namespace Keyring;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Contracts\Factor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Factors\RecoveryCodes;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Duration;

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
            ?? $this->all()->first(fn (Authenticator $authenticator) => ! $authenticator->isVirtual());
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
     */
    public function hasFactorToRecover(): bool
    {
        return $this->all()->contains($this->isFactor(...));
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
     * Whether the account has had the authenticator long enough to count on
     * it: for "authenticator_changes.established_after". Only factors and
     * recovery codes can be anything else. An emailed code and what isn't
     * stored, like the password, always are.
     */
    public function isEstablished(Authenticator $authenticator): bool
    {
        if (! $this->isFactor($authenticator) && $authenticator->factor !== RecoveryCodes::KEY) {
            return true;
        }

        return $authenticator->created_at === null
            || $authenticator->created_at->lte(Duration::ago(config('keyring.authenticator_changes.established_after')));
    }

    /**
     * The keyring without the factors that aren't established yet: what
     * policies like noDowngrade() go by, so that a factor added from a
     * stolen session can sign in, but can't shut out the owner's.
     */
    public function established(): static
    {
        return $this->without(...$this->all()->reject($this->isEstablished(...))->all());
    }

    /**
     * Whether it's a stored factor, rather than recovery codes or a step
     * like an emailed code.
     */
    protected function isFactor(Authenticator $authenticator): bool
    {
        return ! $authenticator->isVirtual()
            && $authenticator->factor !== RecoveryCodes::KEY
            && array_any($authenticator->factor()->categories($authenticator), fn (Category $category) => $category->authenticates());
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
     *
     * A key that isn't established yet counts as a factor, but not as a
     * phishing-resistant, device-bound or attested one: otherwise a key
     * added from a stolen session would be all an ifEnrolled() policy that
     * asks for one took, and the owner, who doesn't have it, would be shut
     * out. It still proves all that when it's used.
     */
    public function reachable(Requirement $requirement): Requirement
    {
        $keyring = $this->withoutFallbacks();
        $provable = array_values($keyring->all()->map($keyring->provableNow(...))->all());

        return $requirement->isMetBy($provable) ? $requirement : $requirement->limitedTo($provable);
    }

    /**
     * What the authenticator would prove, as far as the account can count
     * on it yet: a key that isn't established is a factor and nothing more.
     */
    protected function provableNow(Authenticator $authenticator): Verification
    {
        $verification = Verification::of($authenticator);

        return $this->isEstablished($authenticator)
            ? $verification
            : new Verification($verification->factor, $verification->authenticator, $verification->categories, at: $verification->at);
    }

    /**
     * What each authenticator would prove, if the user verified them all.
     *
     * @return list<Verification>
     */
    protected function provable(): array
    {
        return array_values($this->all()->map(fn (Authenticator $authenticator) => Verification::of($authenticator))->all());
    }

    /**
     * Authenticators that would bring the verifications closer to the
     * requirement. These are what a challenge or a step-up offers, so a
     * factor that can only start a login isn't among them.
     *
     * @param  list<Verification>  $verifications
     * @return Collection<int, Authenticator>
     */
    public function usefulFor(Requirement $requirement, array $verifications): Collection
    {
        $used = array_filter(array_map(fn (Verification $verification) => $verification->authenticator ?? $verification->factor, $verifications));

        return $this->all()
            ->reject(fn (Authenticator $authenticator) => in_array($authenticator->id, $used, true))
            ->reject(fn (Authenticator $authenticator) => ($factor = $authenticator->factor()) instanceof PrimaryFactor && ! $factor->answersChallenges())
            ->filter(fn (Authenticator $authenticator) => $requirement->wouldProgress($verifications, Verification::of($authenticator)))
            ->reject(fn (Authenticator $authenticator) => $authenticator->factor === RecoveryCodes::KEY && ! $this->codeCouldFinish($requirement, $verifications, $authenticator))
            ->values();
    }

    /**
     * Whether spending a recovery code could finish the attempt. A code
     * stands in for a lost possession factor, so what's left must not need
     * another one, or it would be spent and the user still stuck. A
     * requirement that refuses codes can't be finished by one at all.
     *
     * @param  list<Verification>  $verifications
     */
    protected function codeCouldFinish(Requirement $requirement, array $verifications, Authenticator $set): bool
    {
        $rest = $this->all()
            ->reject(fn (Authenticator $other) => in_array(Category::Possession, $other->factor()->categories($other), true))
            ->map(fn (Authenticator $other) => Verification::of($other))
            ->all();

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
