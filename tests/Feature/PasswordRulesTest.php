<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use Illuminate\Hashing\HashManager;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Keyring\Enums\Assurance;
use Keyring\KeyringServiceProvider;
use Keyring\Models\Authenticator;
use Keyring\Rules\CurrentPassword;
use Keyring\Support\PasswordRules;
use Keyring\Tests\Fixtures\User;

function passes(string $password, mixed ...$arguments): bool
{
    return Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for(...$arguments)])->passes();
}

it('refuses a configured minimum under eight characters, at boot and wherever it\'s read', function (string $option, mixed $min) {
    config(["keyring.passwords.{$option}" => $min]);
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $message = "[keyring.passwords.{$option}] option is ".json_encode($min).'. A password needs at least 8 characters';

    expect(fn () => new KeyringServiceProvider(app())->boot())->toThrow(LogicException::class, $message)
        ->and(fn () => PasswordRules::for($option === 'min_with_mfa' ? $user : null))->toThrow(LogicException::class, $message);
})->with([
    ['min_with_mfa', 4],
    ['min_with_mfa', 7],
    ['min_without_mfa', 4],
    ['min_without_mfa', 0],
    ['min_without_mfa', null],
    ['min_without_mfa', 'twelve'],
]);

it('takes a configured minimum of eight or more, as a number or a string from the environment', function () {
    config(['keyring.passwords.min_with_mfa' => 8, 'keyring.passwords.min_without_mfa' => '10']);

    new KeyringServiceProvider(app())->boot();

    expect(PasswordRules::min(withMfa: true))->toBe(8)
        ->and(PasswordRules::min())->toBe(10)
        ->and(passes('qz7vbn3k9x'))->toBeTrue()
        ->and(passes('qz7vbn3k9'))->toBeFalse();
});

it('refuses the most common passwords even when the breach check doesn\'t run', function () {
    // With a second factor the minimum is 8, where most common passwords are.
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    expect(passes('qz7vbn3k', $user))->toBeTrue()
        ->and(passes('sunshine', $user))->toBeFalse()
        ->and(passes('SunShine', $user))->toBeFalse();
});

it('refuses common passwords long enough to stand without a second factor', function () {
    expect(passes('a long passphrase for me'))->toBeTrue()
        ->and(passes('1qaz2wsx3edc4rfv'))->toBeFalse()
        ->and(passes('123456789qwerty'))->toBeFalse()
        ->and(passes('Qazwsxedcrfvtgb'))->toBeFalse();
});

it('refuses a common password whatever its case, and with spaces around it', function () {
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    // "Password1" in the source list, kept lowercased.
    expect(passes('password1', $user))->toBeFalse()
        ->and(passes('Password1', $user))->toBeFalse()
        ->and(passes('PASSWORD1', $user))->toBeFalse()
        ->and(passes(' password1 ', $user))->toBeFalse()
        ->and(passes("\tPassword1\n", $user))->toBeFalse()
        ->and(passes('      1qaz2wsx3edc4rfv      '))->toBeFalse();
});

it('keeps a common password list of the size and shape the rules rely on', function () {
    $lines = explode("\n", file_get_contents(__DIR__.'/../../resources/passwords/common.txt'));

    // One entry per line and a newline after the last.
    expect(array_pop($lines))->toBe('');

    $sorted = $lines;
    sort($sorted, SORT_STRING);

    // OWASP ASVS 6.2.4 asks for the top 3,000 that fit the policy, which
    // has two minimum lengths. Rebuilding the list changes these on purpose.
    expect($lines)->toHaveCount(13052)
        ->and(array_filter($lines, fn (string $line) => mb_strlen($line) >= 15))->toHaveCount(3001)
        ->and(array_filter($lines, fn (string $line) => mb_strlen($line) < PasswordRules::SHORTEST))->toBeEmpty()
        // Looked up trimmed and lowercased, so stored that way, in plain ASCII.
        ->and(array_filter($lines, fn (string $line) => preg_match('/^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/', $line) !== 1 || $line !== strtolower($line)))->toBeEmpty()
        ->and(array_unique($lines))->toHaveCount(count($lines))
        ->and($lines)->toBe($sorted);
});

it('refuses every password in its common list', function () {
    $lines = file(__DIR__.'/../../resources/passwords/common.txt', FILE_IGNORE_NEW_LINES);
    $rule = collect(PasswordRules::for())->first(fn (mixed $rule) => $rule instanceof Closure);

    $missed = array_filter($lines, function (string $line) use ($rule) {
        $refused = false;
        $rule('password', strtoupper($line), function () use (&$refused) {
            $refused = true;
        });

        return ! $refused;
    });

    expect($missed)->toBeEmpty();
});

// NIST SP 800-63B compares the whole password with the words it shouldn't
// be, not the words inside it: a passphrase with a name in it is fine.
it('refuses a password made up of the user\'s name, their email username or the site\'s name', function () {
    config(['app.name' => 'Keyring Example']);
    $user = taylor(['name' => 'Taylor Otwell', 'email' => 'tayotw@example.com']);

    expect(passes('taylor otwell keyring', $user))->toBeFalse()
        ->and(passes('TaylorOtwell-Taylor', $user))->toBeFalse()
        ->and(passes('tayotw.keyring.example', $user))->toBeFalse()
        ->and(passes('keyring example 2026!!', $user))->toBeFalse()
        ->and(passes('keyringkeyringkeyring', $user))->toBeFalse();
});

it('takes a passphrase that only has one of those words in it', function () {
    config(['app.name' => 'Keyring Example']);
    $user = taylor(['name' => 'Taylor Otwell', 'email' => 'tayotw@example.com']);

    expect(passes('a long passphrase for me', $user))->toBeTrue()
        ->and(passes('otwell is my long passphrase', $user))->toBeTrue()
        ->and(passes('taylor rides a blue bicycle', $user))->toBeTrue()
        ->and(passes('keyring was here for ages', $user))->toBeTrue()
        ->and(passes('a tailor made long passphrase', $user))->toBeTrue();
});

it('checks the words it\'s given before there\'s a user, ignoring short ones', function () {
    expect(passes('jordan rivers jordan', context: ['Jordan Rivers', 'jr@example.com']))->toBeFalse()
        ->and(passes('jordan rivers long phrase', context: ['Jordan Rivers', 'jr@example.com']))->toBeTrue()
        // "jr" and "jo" are too short to count, so this is not made of the user's words.
        ->and(passes('jr jo jr jo jr jo jr jo', context: ['Jo', 'jr@example.com']))->toBeTrue();
});

it('refuses a password that isn\'t text without reading it for the user\'s words', function (mixed $password) {
    $errors = Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for(taylor())])->errors()->all();

    expect($errors)->toContain(__('validation.string', ['attribute' => 'password']))
        ->not->toContain(__('keyring::keyring.password_context'))
        ->not->toContain(__('keyring::keyring.password_common'));
})->with([
    'a list of the user\'s words' => [['taylor', 'taylor']],
    'a number' => [12345678],
]);

it('refuses the words the app lists as its own', function () {
    expect(passes('falcon project acme'))->toBeTrue();

    // Keyed or not, and whatever else ends up in the list.
    config(['keyring.passwords.context' => ['project' => 'Falcon Project', 'ACME', 42, null]]);

    expect(passes('falcon project acme'))->toBeFalse()
        ->and(passes('Falcon-Project-2026!'))->toBeFalse()
        ->and(passes('the falcon lands at midnight'))->toBeTrue()
        // And for a user, beside their own names.
        ->and(passes('Falcon Project Taylor', taylor()))->toBeFalse();

    // One word on its own, or a config cached before the option existed.
    config(['keyring.passwords.context' => 'Roadrunner']);
    expect(passes('roadrunner roadrunner'))->toBeFalse();

    config(['keyring.passwords.context' => null]);
    expect(passes('roadrunner roadrunner'))->toBeTrue();
});

it('counts the app\'s name as a whole, however the password separates its words', function () {
    config(['app.name' => 'My App']);

    expect(passes('myapp myapp myapp'))->toBeFalse()
        ->and(passes('MyApp2026MyApp2026'))->toBeFalse()
        ->and(passes('my-app my.app my app'))->toBeFalse()
        // Neither word counts on its own: each is under four characters.
        ->and(passes('my my my my app app app'))->toBeTrue()
        ->and(passes('i work at My App now'))->toBeTrue();
});

it('counts a short name from three characters when it\'s a whole name, and not below', function () {
    config(['app.name' => 'IBM', 'keyring.passwords.context' => ['HP', 'Box Drive']]);
    $amy = taylor(['name' => 'Amy Lee', 'email' => 'amy@abc.example']);

    expect(passes('ibm ibm ibm ibm ibm'))->toBeFalse()
        ->and(passes('I.B.M. I.B.M. I.B.M.'))->toBeFalse()
        ->and(passes('boxdrive boxdrive'))->toBeFalse()
        ->and(passes('hp hp hp hp hp hp hp hp'))->toBeTrue()
        // "Box" is one word of a longer name, and the user's are never whole names.
        ->and(passes('box box box box box'))->toBeTrue()
        ->and(passes('amy lee amy lee abc', $amy))->toBeTrue();
});

it('counts the organisation in the user\'s email address, unless anyone can have one there', function (string $email, string $password, bool $passes) {
    expect(passes($password, taylor(['email' => $email])))->toBe($passes)
        ->and(passes($password, context: ['Taylor', $email]))->toBe($passes);
})->with([
    'the company\'s domain' => ['taylor@megacorp.example', 'megacorp megacorp', false],
    'in any case' => ['taylor@MegaCorp.example', 'MEGACORP-TAYLOR-2026', false],
    'its first label only' => ['taylor@mail.megacorp.example', 'megacorp megacorp', true],
    'a hyphenated one, word by word' => ['taylor@mega-widgets.example', 'widgets mega widgets', false],
    'the rest of the domain' => ['taylor@megacorp.example', 'example example example', true],
    'a public provider' => ['taylor@gmail.com', 'gmail gmail gmail gmail', true],
    'a public provider elsewhere' => ['taylor@yahoo.co.uk', 'yahoo yahoo yahoo yahoo', true],
    'a short label' => ['taylor@abc.example', 'abc abc abc abc abc abc', true],
]);

it('reads look-alike characters as the letters they stand for', function (string $password) {
    config(['app.name' => 'Keyring Example', 'keyring.passwords.context' => ['Cash Desk']]);
    $user = taylor(['name' => 'Taylor Otwell', 'email' => 'tayotw@megacorp.example']);

    expect(passes($password, $user))->toBeFalse();
})->with([
    'k3yr1ng 3x4mpl3 k3yr1ng',
    'K3YRLNG-K3YRLNG-K3YRLNG',
    '0tw3ll 7@yl0r 0tw3ll',
    '7ay07w.m3g4c0rp.7ay07w',
    'ca$h d35k c4$hd35k',
    'keyring2026example1999',
]);

it('still takes a password that only looks a little like a name', function () {
    config(['app.name' => 'Keyring Example']);
    $user = taylor(['name' => 'Taylor Otwell']);

    expect(passes('k3yr1ng was here for ages', $user))->toBeTrue()
        ->and(passes('a tailor made long passphrase', $user))->toBeTrue()
        ->and(passes('4 l0ng p455phr453 f0r m3', $user))->toBeTrue()
        // No longer a false alarm: "million" isn't made of anyone's name.
        ->and(passes('a million reasons to stay', taylor(['name' => 'Lili', 'email' => 'lili@example.com'])))->toBeTrue();
});

it('takes passwords of any composition, and lets an app ask for more length instead', function () {
    expect(passes('  . , ; : ! ? - _  '))->toBeTrue()
        ->and(passes('!?.,;:-_()[]{}<>'))->toBeTrue()
        ->and(passes('alllowercaselettersonly'))->toBeTrue()
        ->and(passes('1357924680135792468'))->toBeTrue()
        ->and(passes('пароль из многих слов'))->toBeTrue()
        ->and(passes('🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑'))->toBeTrue();

    // The example in the docs: a longer minimum for some users.
    $longer = fn (Password $rule) => $rule->rules(['min:20']);

    expect(passes('a long passphrase', adjust: $longer))->toBeFalse()
        ->and(passes('a long passphrase for me', adjust: $longer))->toBeTrue();
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

describe('when the breach check can\'t be reached', function () {
    beforeEach(function () {
        config(['keyring.passwords.uncompromised' => true]);

        $this->password = 'a long passphrase for me';
        $this->hash = strtoupper(sha1($this->password));

        $this->errors = fn (?string $password = null) => Validator::make(
            ['password' => $password ?? $this->password, 'password_confirmation' => $password ?? $this->password],
            ['password' => PasswordRules::for()],
        )->errors()->all();

        // A range as Have I Been Pwned sends it: other hashes, and padding that counts zero.
        $this->range = fn (string ...$lines) => Http::response(implode("\r\n", [
            '0018A45C4D1DEF81644B54AB7F969B88D65:21',
            '00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2',
            '011053FD0102E94D6AE2F8B83D76FAF94F6:0',
            ...$lines,
        ]));
    });

    dataset('no answer', [
        'the service is down' => [fn () => Http::response('', 503)],
        'it limits the app' => [fn () => Http::response('Rate limit is exceeded.', 429)],
        'the connection fails' => [fn () => throw new ConnectionException('Could not resolve host.')],
        'something else answers' => [fn () => Http::response('<html>Sign in to the wifi</html>')],
        'nothing comes back' => [fn () => Http::response('')],
    ]);

    it('lets the password through by default, as laravel does', function (Closure $answer) {
        Http::fake(['api.pwnedpasswords.com/*' => $answer]);
        Exceptions::fake();

        expect(($this->errors)())->toBe([]);
    })->with('no answer');

    it('refuses the password instead when told to, and says why', function (Closure $answer) {
        config(['keyring.passwords.refuse_unchecked' => true]);
        Http::fake(['api.pwnedpasswords.com/*' => $answer]);
        Exceptions::fake();

        expect(($this->errors)())->toBe([__('keyring::keyring.password_unchecked')]);
    })->with('no answer');

    it('still tells a breached password from a clean one', function (?string $count, bool $breached) {
        config(['keyring.passwords.refuse_unchecked' => true]);
        $listed = $count === null ? [] : [substr($this->hash, 5).':'.$count];

        Http::fake(['api.pwnedpasswords.com/*' => ($this->range)(...$listed)]);
        expect(($this->errors)())->toBe($breached ? [__('validation.password.uncompromised', ['attribute' => 'password'])] : []);

        // However the service writes its hashes.
        Http::swap(new Factory);
        Http::fake(['api.pwnedpasswords.com/*' => ($this->range)(...array_map(strtolower(...), $listed))]);
        expect(($this->errors)())->toBe($breached ? [__('validation.password.uncompromised', ['attribute' => 'password'])] : []);
    })->with([
        'not listed' => [null, false],
        // Padding can't name a real hash, but a zero is never a breach.
        'listed as padding' => ['0', false],
        'seen once' => ['1', true],
        'seen often' => ['3861493', true],
        'seen ten times' => ['10', true],
    ]);

    it('only sends the first five characters of the hash', function () {
        config(['keyring.passwords.refuse_unchecked' => true]);
        Http::fake(['api.pwnedpasswords.com/*' => ($this->range)()]);

        ($this->errors)();

        Http::assertSentCount(1);
        Http::assertSent(fn (Request $request) => $request->url() === 'https://api.pwnedpasswords.com/range/'.substr($this->hash, 0, 5)
            && $request->hasHeader('Add-Padding', 'true')
            && ! str_contains($request->url().$request->body(), substr($this->hash, 5)));
    });

    // OWASP ASVS 5.0.0, 15.3.2: an outbound call doesn't go where a
    // redirect sends it.
    it('follows no redirect, and counts one as no answer', function (int $status) {
        config(['keyring.passwords.refuse_unchecked' => true]);
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response('', $status, ['Location' => 'https://elsewhere.example/range/'.substr($this->hash, 0, 5)]),
            // Somewhere that would call every password clean.
            'elsewhere.example/*' => ($this->range)(),
        ]);

        expect(($this->errors)())->toBe([__('keyring::keyring.password_unchecked')]);

        Http::assertSentCount(1);
        Http::assertNotSent(fn (Request $request) => ! str_starts_with($request->url(), 'https://api.pwnedpasswords.com/'));
    })->with([301, 302, 307, 308]);

    it('asks nothing about a password too short to be taken, or with the breach check off', function () {
        config(['keyring.passwords.refuse_unchecked' => true]);
        Http::fake(['api.pwnedpasswords.com/*' => Http::response('', 503)]);

        expect(($this->errors)('too short'))->toHaveCount(1)->not->toContain(__('keyring::keyring.password_unchecked'));

        config(['keyring.passwords.uncompromised' => false]);
        expect(($this->errors)())->toBe([]);

        // Null is production only.
        config(['keyring.passwords.uncompromised' => null]);
        expect(($this->errors)())->toBe([]);

        Http::assertNothingSent();
    });
});

describe('how long a password can be', function () {
    dataset('64 characters', [
        'plain' => [str_repeat('k9$Tq2!x', 8)],
        'accented' => [str_repeat('é', 64)],
        'cyrillic' => [str_repeat('жщюя', 16)],
        'japanese' => [str_repeat('鍵を守る', 16)],
        'emoji' => [str_repeat('🔑', 64)],
    ]);

    it('takes 64 characters of any script with argon2id, and everything up to the maximum', function (string $password) {
        config(['hashing.driver' => 'argon2id']);

        expect(mb_strlen($password))->toBe(64)
            ->and(passes($password))->toBeTrue()
            ->and(passes(str_repeat($password, 2)))->toBeTrue()
            ->and(passes(str_repeat($password, 2).'!'))->toBeFalse();
    })->with('64 characters');

    it('stops at 72 bytes with bcrypt, and says so', function (string $password) {
        $errors = Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for()])->errors();

        strlen($password) <= 72
            ? expect($errors->all())->toBe([])
            : expect($errors->all())->toBe([__('keyring::keyring.password_too_long', ['attribute' => 'password'])])
                ->and($errors->first())->toContain('72 bytes')->toContain('fewer with accented letters, other alphabets or emoji');
    })->with('64 characters');

    it('refuses a NUL byte with bcrypt, which can\'t hash one, and takes it with argon2id', function () {
        $password = "correct horse\0battery staple";
        $errors = fn () => Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for()])->errors()->all();

        expect($errors())->toBe([__('keyring::keyring.password_null_byte', ['attribute' => 'password'])]);

        config(['hashing.driver' => 'argon2id']);

        expect($errors())->toBe([]);
    });
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

        // Nothing is checked for them at all: the time is spent making a
        // hash of something random.
        expect($checked->getArrayCopy())->toBeEmpty();
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

    it('refuses an over-long password in the current password rule on its own', function () {
        $checked = recordHashChecks();
        $user = taylor(['password' => $this->exact]);

        $errors = fn (mixed $current) => Validator::make(['current_password' => $current], ['current_password' => new CurrentPassword($user)])->errors()->all();

        expect($errors($this->tooLong))->toBe($errors('wrong'))->toBe([__('validation.current_password')])
            ->and($errors(['an', 'array']))->toBe([__('validation.current_password')])
            ->and($errors($this->exact))->toBe([])
            ->and($checked->getArrayCopy())->not->toContain($this->tooLong);
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
