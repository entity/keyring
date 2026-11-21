<?php

declare(strict_types=1);

namespace Keyring\Console;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\SessionsRevoked;
use Keyring\Facades\Keyring;
use Keyring\Sessions\Sessions;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * For whoever runs the app: end one user's sessions, or everyone's, without
 * waiting for them to time out. A stolen laptop, an account that was got
 * into, a leaked APP_KEY.
 */
#[AsCommand(name: 'keyring:sign-out')]
#[Description('Sign one user out of every session, or every user with --all')]
#[Signature('keyring:sign-out
        {user? : The user\'s ID, or their username}
        {--id : Read the user as an ID only, when it is also someone else\'s username}
        {--all : Sign every user out}
        {--force : Sign every user out without asking first}')]
class SignOutCommand extends Command
{
    public function handle(Sessions $sessions, SessionRegistry $registry): int
    {
        $name = $this->argument('user');

        if ($this->option('all') === ($name !== null)) {
            $this->components->error('Name one user to sign out, or pass --all to sign out everyone.');

            return self::INVALID;
        }

        return is_string($name) ? $this->one($sessions, $name) : $this->everyone($registry);
    }

    /**
     * Every session ends, and with it what "remember me" could bring back.
     * Trusted devices, pending email changes and passwords are left as they
     * are: this signs people out, it doesn't say their accounts were taken.
     */
    protected function everyone(SessionRegistry $registry): int
    {
        if (! $this->option('force') && ! $this->confirm('Sign every user out of every session?')) {
            $this->components->warn('Nobody was signed out.');

            return self::FAILURE;
        }

        $registry->revokeEveryone();

        $this->components->info('Signed everyone out. Each browser finds out on its next request.');

        return self::SUCCESS;
    }

    protected function one(Sessions $sessions, string $name): int
    {
        $found = $this->find($name);

        if ($found->count() !== 1) {
            $this->components->error($found->isEmpty()
                ? "No user has the ID or username [{$name}]."
                : "[{$name}] could be {$found->map($this->describe(...))->join(' or ')}. Pass --id with the ID of the one you mean.");

            return self::FAILURE;
        }

        $user = $found->sole();
        $count = $sessions->because(SessionEndReason::SignedOutEverywhere, fn () => $sessions->signOutEverywhere($user));

        SessionsRevoked::dispatch($user, $count);

        $this->components->info(sprintf('Signed out %s: %d %s ended.', $this->describe($user), $count, $count === 1 ? 'session' : 'sessions'));

        return self::SUCCESS;
    }

    protected function describe(Authenticatable&Model $user): string
    {
        return "{$user->getAttribute(Keyring::username())} (ID {$user->getKey()})";
    }

    /**
     * Whoever goes by the name: the user with that ID and the user with that
     * username, who are usually the same person or only one of them. Both
     * are looked for, so a name that could mean two people signs out neither.
     *
     * @return Collection<int, Authenticatable&Model>
     */
    protected function find(string $name): Collection
    {
        $provider = Keyring::provider();

        return new Collection([
            $this->couldBeKey($name) ? $provider->retrieveById($name) : null,
            $this->option('id') ? null : $provider->retrieveByCredentials([Keyring::username() => Keyring::normalizeUsername($name)]),
        ])
            ->filter(fn (?Authenticatable $user) => $user instanceof Model)
            ->unique(fn (Authenticatable&Model $user) => $user->getKey())
            ->values();
    }

    /**
     * Whether the name is shaped like one of the model's keys. Some
     * databases refuse to compare an email address with a number or a UUID,
     * and say so with an error.
     */
    protected function couldBeKey(string $name): bool
    {
        $provider = Keyring::provider();

        if (! $provider instanceof EloquentUserProvider) {
            return true;
        }

        $model = $provider->createModel();

        return match (true) {
            method_exists($model, 'isValidUniqueId') => $model->isValidUniqueId($name),
            $model->getKeyType() === 'int' => ctype_digit($name) && strlen($name) <= 18,
            default => true,
        };
    }
}
