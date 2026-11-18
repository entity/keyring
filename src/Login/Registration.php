<?php

declare(strict_types=1);

namespace Keyring\Login;

use Closure;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\ReservedAddresses;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Exceptions\MissingNotification;
use Keyring\KeyringManager;
use Keyring\Support\Duration;
use Keyring\Support\Input;
use Keyring\Support\PasswordRules;
use Keyring\Support\Throttle;
use Keyring\Support\Url;
use LogicException;
use Throwable;

use function Illuminate\Support\defer;

/**
 * Registering. The app's action validates the form and creates the user;
 * whether the address is free is Keyring's to decide, so the action can't
 * give it away.
 *
 * By default nobody can use the form to find out who has an account. A free
 * address, a taken one, one reserved for its previous owner and one whose
 * account the app keeps out get the same answer, in the same time, after the
 * same validation. A new user is left signed out and emailed a verification
 * link, and a taken address is emailed that someone tried to register with
 * it. With the "registration.reveal_taken" option the form says when an
 * address is taken instead, and new users are signed in.
 */
class Registration
{
    public function __construct(
        protected Container $container,
        protected KeyringManager $keyring,
        protected ReservedAddresses $reserved,
        protected Throttle $throttle,
    ) {}

    /**
     * Refuse a setup that couldn't finish a registration, before anything
     * is saved and the address is taken by an account nobody can use.
     *
     * @throws EmailVerificationRequired
     * @throws MissingNotification
     */
    public function ensureReady(): void
    {
        $provider = $this->keyring->provider();
        $model = $provider instanceof EloquentUserProvider ? $provider->getModel() : null;
        $verifies = $model !== null && is_a($model, MustVerifyEmail::class, true);

        throw_if($verifies && ! Route::has('verification.verify'), EmailVerificationRequired::forRegistration((string) $model));

        if ($this->keyring->hidesRegisteredAddresses()) {
            throw_unless($verifies, EmailVerificationRequired::forHiddenRegistration((string) $model));
            throw_unless($this->keyring->hasNotification('already_registered'), MissingNotification::for('already_registered'));
        }
    }

    /**
     * Register without giving away whether the address had an account. The
     * caller answers the same way whatever happened here.
     *
     * Inside a timebox that's never left early, so a refused form, a new
     * account and a taken address all take as long, and every email goes out
     * after the response. Each path makes one password hash, the slowest
     * thing either does.
     *
     * Anything the action's create() throws is reported and answered like
     * the rest, with nothing sent. A ValidationException is the action
     * refusing the form on purpose, and is passed on.
     *
     * @throws ValidationException
     */
    public function quietly(Request $request, CreatesNewUsers $creator): void
    {
        $this->container->make(Timebox::class)->call(function () use ($request, $creator) {
            $input = $this->validate($request, $creator);
            $email = $this->address($request, $input);

            try {
                $user = $this->taken($email) ? null : $this->create($creator, $input, $email);
            } catch (ValidationException $e) {
                throw $e;
            } catch (Throwable $e) {
                report($e);

                return;
            }

            if ($user !== null) {
                // Laravel's listener mails the verification link, which would
                // show in how long a free address takes to answer.
                defer(function () use ($user, $email) {
                    // Counted with what the address is sent if it's tried again.
                    $this->throttle->notifying('registration', 'mail:'.$email);

                    event(new Registered($user));
                });

                return;
            }

            // As much work as creating the account: the hash of its password.
            Hash::make(Str::random(32));

            $pending = $this->pending($email);

            defer(fn () => $this->tell($email, $pending));
        }, Duration::milliseconds(config('keyring.timebox')) * 1000);
    }

    /**
     * Register, saying so when the address is taken, next to whatever else
     * is wrong with the form.
     *
     * @throws ValidationException
     */
    public function openly(Request $request, CreatesNewUsers $creator): Authenticatable&Model
    {
        try {
            $input = $this->validate($request, $creator);
        } catch (ValidationException $e) {
            if ($this->taken($email = $this->address($request))) {
                $e->validator->errors()->merge($this->alreadyTaken($email)->errors());
            }

            throw $e;
        }

        $email = $this->address($request, $input);

        $user = $this->taken($email) ? null : $this->create($creator, $input, $email);

        return $user ?? throw $this->alreadyTaken($email);
    }

    /**
     * The action's validation, then Keyring's own check that the password
     * can be hashed: whatever rules the action has, a password the hasher
     * would refuse is refused here, the same for every address, rather than
     * failing only where an account is created.
     *
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    protected function validate(Request $request, CreatesNewUsers $creator): array
    {
        $input = $creator->validate($this->input($request));

        Validator::make($input, ['password' => [PasswordRules::hashable()]])->validate();

        return $input;
    }

    /**
     * The form, with its password as it will be hashed and checked from now
     * on, so the action's rules measure that.
     *
     * @return array<string, mixed>
     */
    protected function input(Request $request): array
    {
        return PasswordRules::normalizeInput(Input::all($request));
    }

    /**
     * Whether nobody new can have the address: an account has it, or it's
     * held for the previous owner while their email change can be undone.
     */
    public function taken(string $email): bool
    {
        // Without global scopes: a soft deleted account, or one the app
        // hides, still holds its address.
        return $this->users()->withoutGlobalScopes()->where($this->keyring->email(), $email)->exists()
            || $this->reserved->has($email);
    }

    /**
     * Null when someone else registered the address in the moment since it
     * was checked (the form sent twice, say), which the users table's unique
     * index refused. It's taken now, and answered like any that is.
     *
     * @param  array<string, mixed>  $input
     */
    protected function create(CreatesNewUsers $creator, array $input, string $email): (Authenticatable&Model)|null
    {
        try {
            // In a transaction of its own, so the refused insert doesn't
            // leave one the caller has open unusable, as PostgreSQL would.
            return $this->model()->getConnection()->transaction(fn () => $creator->create($input));
        } catch (UniqueConstraintViolationException $e) {
            return $this->taken($email) ? null : throw $e;
        }
    }

    /**
     * Laravel's "has already been taken" on the address, as a unique rule
     * would say it.
     */
    protected function alreadyTaken(string $email): ValidationException
    {
        $field = $this->keyring->email();

        return new ValidationException(Validator::make([$field => $email], [
            $field => fn (string $attribute, mixed $value, Closure $fail) => $fail('validation.unique')->translate(),
        ]));
    }

    /**
     * The address as the action validated it, which is how it's stored.
     *
     * @param  array<string, mixed>  $input
     */
    protected function address(Request $request, array $input = []): string
    {
        $field = $this->keyring->email();
        $address = $input[$field] ?? null;

        return $this->keyring->normalizeUsername(is_string($address) ? $address : Input::text($request, $field));
    }

    /**
     * The account holding the address, when nobody has verified it yet:
     * whoever registered it may have lost the link, or let it expire.
     */
    protected function pending(string $email): (Authenticatable&MustVerifyEmail&Model)|null
    {
        $user = $this->users()->where($this->keyring->email(), $email)->first();

        return $user instanceof Authenticatable && $user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail() ? $user : null;
    }

    /**
     * Mail a taken address, after the response: another verification link
     * for an account that's still waiting for one, and otherwise that
     * someone tried to register with it. Counted per address like any
     * notice, so the form can't be used to mail one without end.
     */
    protected function tell(string $email, (MustVerifyEmail&Model)|null $pending): void
    {
        if ($this->throttle->notifying('registration', 'mail:'.$email) !== null) {
            return;
        }

        if ($pending !== null) {
            $pending->sendEmailVerificationNotification();

            return;
        }

        Notification::route('mail', $email)->notify($this->keyring->requiredNotification('already_registered', [
            'loginUrl' => Url::route('login'),
            'resetUrl' => Route::has('password.request') ? Url::route('password.request') : null,
        ]));
    }

    /**
     * @return Builder<Authenticatable&Model>
     */
    protected function users(): Builder
    {
        return $this->model()->newQuery();
    }

    protected function model(): Authenticatable&Model
    {
        $provider = $this->keyring->provider();

        throw_unless($provider instanceof EloquentUserProvider, LogicException::class, 'Keyring checks whether an address is taken through the guard\'s Eloquent user provider. Check the "guard" option in config/keyring.php against config/auth.php.');

        return $provider->createModel();
    }
}
