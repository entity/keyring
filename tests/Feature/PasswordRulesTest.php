<?php

use Illuminate\Contracts\Container\Container;
use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Keyring\Enums\Assurance;
use Keyring\Models\Authenticator;
use Keyring\Support\PasswordRules;
use Keyring\Tests\Fixtures\User;

function passes(string $password, mixed ...$arguments): bool
{
    return Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for(...$arguments)])->passes();
}

it('refuses the most common passwords even when the breach check doesn\'t run', function () {
    // With a second factor the minimum is 8, where most common passwords are.
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    expect(passes('qz7vbn3k', $user))->toBeTrue()
        ->and(passes('sunshine', $user))->toBeFalse()
        ->and(passes('SunShine', $user))->toBeFalse();
});

it('refuses passwords containing the user\'s name, their email username or the site\'s name', function () {
    config(['app.name' => 'Keyring Example']);
    $user = taylor(['name' => 'Taylor Otwell', 'email' => 'tayotw@example.com']);

    expect(passes('a long passphrase for me', $user))->toBeTrue()
        ->and(passes('otwell is my long passphrase', $user))->toBeFalse()
        ->and(passes('my long passphrase tayotw', $user))->toBeFalse()
        ->and(passes('keyring was here for ages', $user))->toBeFalse();
});

it('checks the words it\'s given before there\'s a user, ignoring short ones', function () {
    expect(passes('jordan rivers long phrase', context: ['Jordan Rivers', 'jr@example.com']))->toBeFalse()
        ->and(passes('a long passphrase with jr in it', context: ['Jo', 'jr@example.com']))->toBeTrue();
});

it('checks the breach list in production only, unless told otherwise', function () {
    $breachCheck = fn () => collect(PasswordRules::for())->contains(fn (mixed $rule) => $rule instanceof Password && (fn () => $this->uncompromised)->call($rule));

    expect($breachCheck())->toBeFalse();

    app()->detectEnvironment(fn () => 'production');
    $inProduction = $breachCheck();
    // Back before teardown, which would ask to confirm migrating in production.
    app()->detectEnvironment(fn () => 'testing');
    expect($inProduction)->toBeTrue();

    config(['keyring.passwords.uncompromised' => false]);
    expect($breachCheck())->toBeFalse();
});

/**
 * Swap in a hash manager that remembers what it was asked to check, whether
 * through a user provider, a validation rule or the facade.
 *
 * @return ArrayObject<int, string>
 */
function recordHashChecks(): ArrayObject
{
    $checked = new ArrayObject;

    Hash::swap(new class(app(), $checked) extends HashManager
    {
        /** @param ArrayObject<int, string> $checked */
        public function __construct(Container $container, private ArrayObject $checked)
        {
            parent::__construct($container);
        }

        public function check($value, $hashedValue, array $options = []): bool
        {
            $this->checked[] = (string) $value;

            return parent::check($value, $hashedValue, $options);
        }
    });

    return $checked;
}

describe('checking a password against its stored hash', function () {
    beforeEach(function () {
        $this->exact = str_repeat('a', 72);
        $this->tooLong = $this->exact.'not-the-password';
    });

    it('only keeps what the stored hash can check in full', function (?string $hash, string $input, bool $kept) {
        expect(PasswordRules::forVerifying($input, $hash) === $input)->toBe($kept);
    })->with([
        'bcrypt at the limit' => ['$2y$12$abc', str_repeat('a', 72), true],
        'bcrypt one byte over' => ['$2y$12$abc', str_repeat('a', 73), false],
        'bcrypt over in bytes but not in characters' => ['$2y$12$abc', str_repeat('ü', 37), false],
        'bcrypt with a NUL byte' => ['$2y$12$abc', "hello\0junk", false],
        'bcrypt from another system ($2a$)' => ['$2a$12$abc', str_repeat('a', 73), false],
        'bcrypt from another system ($2b$)' => ['$2b$12$abc', str_repeat('a', 73), false],
        'bcrypt from another system ($2x$)' => ['$2x$12$abc', str_repeat('a', 73), false],
        'argon2id takes any length' => ['$argon2id$v=19$abc', str_repeat('a', 500), true],
        'argon2i takes any length' => ['$argon2i$v=19$abc', str_repeat('a', 500), true],
        'no stored hash' => [null, str_repeat('a', 73), true],
    ]);

    it('fails an over-long password at login exactly like a wrong one, without hashing it', function () {
        $checked = recordHashChecks();
        taylor(['password' => $this->exact]);

        $error = fn (string $password) => $this->post('/login', ['email' => 'taylor@example.com', 'password' => $password])
            ->assertSessionHasErrors('email')->getSession()->get('errors')->first('email');

        expect($error($this->tooLong))->toBe($error('wrong'))->toBe(__('auth.failed'));
        $this->assertGuest();
        expect($checked->getArrayCopy())->toHaveCount(2)->not->toContain($this->tooLong);
    });

    it('signs in with a password of exactly the limit', function () {
        taylor(['password' => $this->exact]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact])->assertRedirect('/dashboard');

        $this->assertAuthenticated();
    });

    it('refuses an over-long password with every optional feature off', function () {
        withFeatures([]);
        taylor(['password' => $this->exact]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->tooLong])->assertSessionHasErrors('email');
        $this->assertGuest();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact])->assertRedirect('/dashboard');
    });

    it('counts an over-long password towards the lockout', function () {
        config(['keyring.limits.per_account' => 2]);
        taylor(['password' => $this->exact]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->tooLong]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->tooLong]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact])->assertSessionHasErrors('email');
        $this->assertGuest();
    });

    it('keeps an over-long password away from the hasher for unknown accounts too', function () {
        $checked = recordHashChecks();

        $this->post('/login', ['email' => 'nobody@example.com', 'password' => $this->tooLong])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        expect($checked->getArrayCopy())->toHaveCount(1)->not->toContain($this->tooLong);
    });

    it('fails an over-long password at step-up, and takes the right one', function () {
        $checked = recordHashChecks();
        Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');
        taylor(['password' => $this->exact]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact]);
        $this->travel(16)->minutes();

        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $this->inertia()->get(route('keyring.confirm.challenge'));

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => $this->tooLong])->assertSessionHasErrors('password');
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        expect($checked->getArrayCopy())->not->toContain($this->tooLong);

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => $this->exact])->assertRedirect('/account');
    });

    it('fails an over-long current password on a change like a wrong one, and takes the right one', function () {
        $checked = recordHashChecks();
        $user = taylor(['password' => $this->exact]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact]);
        $new = 'correct horse battery staple';

        $change = fn (string $current) => $this->putJson(route('user-password.update'), [
            'current_password' => $current,
            'password' => $new,
            'password_confirmation' => $new,
        ]);

        expect($change($this->tooLong)->assertJsonValidationErrors('current_password')->json('errors.current_password'))
            ->toBe($change('wrong')->assertJsonValidationErrors('current_password')->json('errors.current_password'));
        expect($checked->getArrayCopy())->not->toContain($this->tooLong)
            ->and(Hash::check($new, $user->fresh()->password))->toBeFalse();

        $change($this->exact)->assertOk();
        expect(Hash::check($new, $user->fresh()->password))->toBeTrue();
    });

    it('fails an over-long password when removing the last second factor, and takes the right one', function () {
        $checked = recordHashChecks();
        $user = taylor(['password' => $this->exact]);
        $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
        $this->actingAs($user)->withAssurance(Assurance::AAL2);

        $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => $this->tooLong])
            ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_to_remove_last_factor')]);
        expect(Authenticator::find($totp->id))->not->toBeNull()
            ->and($checked->getArrayCopy())->not->toContain($this->tooLong);

        $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => $this->exact])->assertOk();
    });

    it('goes by the stored hash after an app moves to argon2', function () {
        config(['hashing.driver' => 'argon2id', 'hashing.argon.verify' => false]);
        $user = taylor();
        User::query()->whereKey($user->id)->update(['password' => password_hash($this->exact, PASSWORD_BCRYPT, ['cost' => 4])]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->tooLong])->assertSessionHasErrors('email');
        $this->assertGuest();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $this->exact])->assertRedirect('/dashboard');
        expect($user->fresh()->password)->toStartWith('$argon2id$');
    })->skip(! defined('PASSWORD_ARGON2ID'), 'Needs PHP built with argon2.');

    it('lets an argon2 hash take a long password', function () {
        config(['hashing.driver' => 'argon2id']);
        $long = str_repeat('a', 100);
        taylor(['password' => $long]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => $long])->assertRedirect('/dashboard');
    })->skip(! defined('PASSWORD_ARGON2ID'), 'Needs PHP built with argon2.');
});
