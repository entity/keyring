<?php

declare(strict_types=1);

use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use App\Providers\KeyringServiceProvider;
use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Encryption\Encrypter;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Contracts\ValidatesEmailChanges;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\RegisteredSession;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SoftDeletingUser;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

describe('keyring:install', function () {
    beforeEach(function () {
        $this->sandbox = sys_get_temp_dir().'/keyring-install-'.uniqid();
        $files = new Filesystem;
        $files->ensureDirectoryExists($this->sandbox.'/bootstrap');
        $files->put($this->sandbox.'/bootstrap/providers.php', "<?php\n\nreturn [\n    App\\Providers\\AppServiceProvider::class,\n];\n");

        $this->app->useAppPath($this->sandbox.'/app');
        $this->app->useBootstrapPath($this->sandbox.'/bootstrap');
    });

    afterEach(function () {
        $files = new Filesystem;
        $files->deleteDirectory($this->sandbox);
        $files->delete(config_path('keyring.php'));
        $files->delete($files->glob(database_path('migrations/*_create_keyring_*')));
    });

    it('installs the password, registration and password resets without asking', function () {
        $this->artisan('keyring:install', ['--no-interaction' => true])->assertSuccessful();

        $config = require config_path('keyring.php');
        $provider = file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php');

        expect($config['features'])->toBe([Features::registration(), Features::resetPasswords()])
            ->and(file_get_contents(config_path('keyring.php')))->toContain('// Features::devices(),')
            // The emails a flow needs are registered, the security notices left for later.
            ->and($provider)->toContain("            'verification_code' => Notifications\VerificationCode::class,")
            ->toContain("            // 'password_changed' => Notifications\PasswordChanged::class,")
            ->toContain("            // 'new_device' => Notifications\NewDevice::class,")
            ->and(glob($this->sandbox.'/app/Notifications/Keyring/*.php'))->toHaveCount(17)
            ->and($provider)->toContain('Password::class,')
            ->not->toContain('Totp')->not->toContain('WebAuthn')->not->toContain('RecoveryCodes')->not->toContain('Keyring::require(')
            // Every action, so turning a feature on later works.
            ->toContain('Keyring::updateUserPasswordsUsing(UpdateUserPassword::class);')
            ->and(array_map(basename(...), glob($this->sandbox.'/app/Actions/Keyring/*.php')))->toEqualCanonicalizing([
                'CreateNewUser.php', 'PasswordValidationRules.php', 'ResetUserPassword.php', 'UpdateUserPassword.php', 'ValidateEmailChange.php',
            ])
            ->and(file_get_contents($this->sandbox.'/bootstrap/providers.php'))->toContain('App\Providers\KeyringServiceProvider::class');

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
    });

    it('adds the sign-in methods and features picked, and what they need', function () {
        $this->artisan('keyring:install', [
            '--factor' => ['totp', 'passkeys'],
            '--feature' => [Features::updatePasswords(), Features::devices()],
            '--no-interaction' => true,
        ])->expectsOutputToContain('Turned on managing sign-in methods')->assertSuccessful();

        $config = require config_path('keyring.php');
        $provider = file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php');

        expect($config['features'])->toBe([Features::updatePasswords(), Features::manageAuthenticators(), Features::devices()])
            // With a second sign-in method, the security emails come too.
            ->and($provider)->toContain("            'recovery_code_used' => Notifications\RecoveryCodeUsed::class,")
            ->toContain("            // 'new_device' => Notifications\NewDevice::class,")
            ->toContain('Totp::class,')->toContain('RecoveryCodes::class,')->toContain('WebAuthn::passkeys(),')->toContain('Keyring::require(')
            ->not->toContain('securityKeys')->not->toContain('EmailCode');

        expectValidPhp($this->sandbox.'/app/Providers/KeyringServiceProvider.php');
        expectValidPhp(config_path('keyring.php'));
    });

    it('adds recovery codes to any second sign-in method, so losing it isn\'t the end of the account', function (string $factor) {
        $this->artisan('keyring:install', ['--factor' => [$factor], '--no-interaction' => true])->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toContain('RecoveryCodes::class,');
    })->with(['passkeys', 'security-keys', 'email-codes']);

    it('turns on email verification when registered users can add sign-in methods', function () {
        $this->artisan('keyring:install', ['--factor' => ['passkeys'], '--feature' => [Features::registration()], '--no-interaction' => true])
            ->expectsOutputToContain('Turned on email verification')
            ->expectsOutputToContain('MustVerifyEmail')
            ->assertSuccessful();

        expect((require config_path('keyring.php'))['features'])->toContain(Features::emailVerification());
    });

    it('refuses sign-in methods and features it doesn\'t know, before writing anything', function () {
        $this->artisan('keyring:install', ['--factor' => ['totpp'], '--feature' => ['devicez'], '--no-interaction' => true])
            ->expectsOutputToContain('Unknown --factor: totpp')
            ->expectsOutputToContain('Unknown --feature: devicez')
            ->assertFailed();

        expect(file_exists(config_path('keyring.php')))->toBeFalse();
    });

    it('can leave out the security emails', function () {
        $this->artisan('keyring:install', ['--factor' => ['totp'], '--no-emails' => true, '--no-interaction' => true])->assertSuccessful();

        expect(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))
            ->toContain("            // 'authenticator_added' => Notifications\AuthenticatorAdded::class,")
            ->toContain("            'email_change_notice' => Notifications\EmailChangeNotice::class,");
    });

    it('asks which sign-in methods and features to set up', function () {
        $this->artisan('keyring:install')
            ->expectsChoice('Which sign-in methods besides the password?', ['passkeys'], ['totp' => 'Authenticator app', 'passkeys' => 'Passkeys', 'security-keys' => 'Security keys, as a second factor', 'email-codes' => 'Email codes, as a second factor (the weakest option)'])
            ->expectsQuestion('Which features?', [Features::resetPasswords(), Features::manageAuthenticators()])
            ->expectsConfirmation('Email users when their password or sign-in methods change?', 'yes')
            ->assertSuccessful();

        expect((require config_path('keyring.php'))['features'])->toBe([Features::resetPasswords(), Features::manageAuthenticators()])
            ->and(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toContain('WebAuthn::passkeys(),')->not->toContain('Totp');
    });

    it('can run again without duplicating migrations or overwriting customised files', function () {
        $this->artisan('keyring:install', ['--no-interaction' => true])->assertSuccessful();
        file_put_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php', '<?php // mine');

        $this->artisan('keyring:install', ['--factor' => ['passkeys'], '--no-interaction' => true])
            ->expectsOutputToContain('keyring.php, it already exists')
            ->doesntExpectOutputToContain('Turned on')
            ->doesntExpectOutputToContain('HasKeyring')
            ->doesntExpectOutputToContain('php artisan migrate')
            ->assertSuccessful();

        expect(glob(database_path('migrations/*_create_keyring_authenticators_table.php')))->toHaveCount(1)
            ->and(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toBe('<?php // mine');
    });
})->skip(fn () => getenv('TEST_TOKEN') !== false, 'Publishes into the testbench app every parallel worker shares.');

function passkeysTable(): void
{
    Schema::create('passkeys', function (Blueprint $table) {
        $table->id();
        $table->foreignId('user_id');
        $table->string('name');
        $table->string('credential_id');
        $table->json('credential');
        $table->timestamp('last_used_at')->nullable();
        $table->timestamps();
    });
}

describe('keyring:import fortify', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, Totp::class, WebAuthn::passkeys(), RecoveryCodes::class]);

        Schema::table('users', function (Blueprint $table) {
            $table->text('two_factor_secret')->nullable();
            $table->text('two_factor_recovery_codes')->nullable();
            $table->timestamp('two_factor_confirmed_at')->nullable();
        });

        $this->user = taylor();
    });

    afterEach(function () {
        Model::encryptUsing(null);
    });

    it('refuses to import into factors that aren\'t registered', function () {
        Keyring::factors([Password::class]);
        DB::table('users')->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain('Register totp, recovery in Keyring::factors() first')
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    });

    it('imports fortify two factor and recovery codes, once', function () {
        $secret = app(Google2FA::class)->generateSecretKey();

        DB::table('users')->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2', 'ZyXwVuTsR9-qPoNmLkJi8'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify', '--dry-run' => true])->assertSuccessful();
        expect(Authenticator::count())->toBe(0);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();
        $this->artisan('keyring:import', ['source' => 'fortify'])->expectsOutputToContain('Already imported')->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp'))->toHaveCount(1)
            ->and($keyring->of('totp')->first()->secret)->toBe($secret)
            ->and($keyring->of('recovery'))->toHaveCount(1);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->get(route('keyring.login.challenge', ['recovery']));
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aBcDeFgHi1-JkLmNoPqR2'])->assertRedirect('/dashboard');
    });

    it('keeps the case of fortify\'s recovery codes, which is what makes them long enough to store hashed', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'abcdefghi1-jklmnopqr2'])->assertSessionHasErrors('code');
        $this->assertGuest();

        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aBcDeFgHi1 JkLmNoPqR2'])->assertRedirect('/dashboard');
    });

    it('leaves behind recovery codes too short to store hashed, and says so', function () {
        $secret = app(Google2FA::class)->generateSecretKey();

        DB::table('users')->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2', 'abcde-12345'])),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped the recovery codes of user {$this->user->id}: they aren't the 20 letters and digits Fortify makes")
            ->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp')->sole()->secret)->toBe($secret)
            ->and($keyring->of('recovery'))->toBeEmpty();
    });

    it('imports unconfirmed secrets only when asked', function () {
        config(['fortify.features' => ['two-factor-authentication'], 'fortify-options.two-factor-authentication' => ['confirm' => true]]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped user {$this->user->id}: its secret was never confirmed")
            ->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

        $this->artisan('keyring:import', ['source' => 'fortify', '--unconfirmed' => true])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });

    it('never brings back what a user removed, or adds to what they set up in keyring', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt(json_encode(['aBcDeFgHi1-JkLmNoPqR2'])),
            'two_factor_confirmed_at' => now(),
        ]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        // The phone is lost: the user swaps the imported app for a new one.
        $this->user->keyring->of('totp')->first()->delete();
        $new = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp')->pluck('id')->all())->toBe([$new->id])
            ->and($keyring->of('recovery'))->toHaveCount(1);

        $other = taylor(['email' => 'abigail@example.com']);
        Authenticator::factory()->securityKey()->for($other, 'authenticatable')->create(['factor' => 'passkey']);
        DB::table('users')->where('id', $other->id)->update(['two_factor_secret' => encrypt('secret'), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped user {$other->id}: they already have sign-in methods in Keyring")
            ->assertSuccessful();
        expect($other->keyring->refresh()->of('totp'))->toBeEmpty();
    });

    it('imports a secret with no confirmation when fortify enforces it without one, and challenges the user', function () {
        config(['fortify.features' => ['two-factor-authentication']]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('asks which rule applies when fortify\'s config can\'t say', function () {
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}: its secret was never confirmed and Fortify's confirm option can't be read.")
            ->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'maybe'])->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'on'])->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

        $this->artisan('keyring:import', ['source' => 'fortify', '--fortify-confirm' => 'off'])->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });

    it('fails closed on a secret it can\'t decrypt, and imports it once it can', function () {
        $secret = app(Google2FA::class)->generateSecretKey();
        DB::table('users')->update([
            'two_factor_secret' => new Encrypter(random_bytes(32), 'aes-256-cbc')->encrypt($secret),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify', '--dry-run' => true])
            ->expectsOutputToContain("Failed user {$this->user->id}: its two factor secret or recovery codes can't be decrypted")
            ->assertFailed();
        expect(Authenticator::count())->toBe(0);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}")
            ->assertFailed();
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($secret)]);
        $this->assertGuest();

        DB::table('users')->update(['two_factor_secret' => encrypt($secret)]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp'))->toHaveCount(1)
            ->and($keyring->of('totp')->first()->secret)->toBe($secret);
    });

    it('fails a row whose recovery codes are in an unexpected format', function () {
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_recovery_codes' => encrypt('not json'),
            'two_factor_confirmed_at' => now(),
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed user {$this->user->id}: its two factor secret or recovery codes are in an unexpected format")
            ->assertFailed();
    });

    it('decrypts with the encrypter eloquent is using', function () {
        $encrypter = new Encrypter(random_bytes(32), 'aes-256-cbc');
        Model::encryptUsing($encrypter);
        $secret = app(Google2FA::class)->generateSecretKey();
        DB::table('users')->update(['two_factor_secret' => $encrypter->encrypt($secret), 'two_factor_confirmed_at' => now()]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect($this->user->keyring->refresh()->of('totp')->first()->secret)->toBe($secret);
    });

    it('reports passkeys it can\'t import', function () {
        passkeysTable();
        DB::table('passkeys')->insert([
            ['id' => 1, 'user_id' => 999, 'name' => 'Orphan', 'credential_id' => 'a', 'credential' => '{}'],
            ['id' => 2, 'user_id' => $this->user->id, 'name' => 'Broken', 'credential_id' => 'b', 'credential' => '{}'],
        ]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed passkey 1 of user 999: that user doesn't exist")
            ->expectsOutputToContain("Failed passkey 2 of user {$this->user->id}: its credential is in an unexpected format")
            ->assertFailed();
        expect(Authenticator::count())->toBe(0);
    });

    it('will not import a passkey whose record it could not read back', function (string $id, string $credential) {
        passkeysTable();
        DB::table('passkeys')->insert(['id' => 1, 'user_id' => $this->user->id, 'name' => 'Junk', 'credential_id' => $id, 'credential' => $credential]);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Failed passkey 1 of user {$this->user->id}: its credential is in an unexpected format")
            ->assertFailed();

        expect(Authenticator::count())->toBe(0);
    })->with([
        'json that is not a credential record' => ['YWJjZGVmZ2g', '{"counter":0}'],
        'an id that is not base64url' => ['not base64url!', '{"counter":0}'],
    ]);

    it('finishes a two factor import that failed before, though the passkey came across', function () {
        $secret = app(Google2FA::class)->generateSecretKey();
        passkeysTable();
        DB::table('users')->update([
            'two_factor_secret' => new Encrypter(random_bytes(32), 'aes-256-cbc')->encrypt($secret),
            'two_factor_confirmed_at' => now(),
        ]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();
        expect(Authenticator::query()->where('factor', 'totp')->sole()->secret)->toBeNull()
            ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);

        DB::table('users')->update(['two_factor_secret' => encrypt($secret)]);
        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'totp')->sole()->secret)->toBe($secret)
            ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
    });

    it('says so when it leaves out a passkey an earlier run did not bring across', function () {
        passkeysTable();
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()), 'two_factor_confirmed_at' => now()]);
        DB::table('passkeys')->insert(['id' => 1, 'user_id' => $this->user->id, 'name' => 'MacBook', 'credential_id' => 'YWJjZGVmZ2g', 'credential' => '{}']);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertFailed();

        DB::table('passkeys')->update(passkeyRow($this->user));

        // It can't tell a row that failed from one the user removed since, so
        // it stays out, and the run says which.
        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped passkey 1 of user {$this->user->id}: an earlier import left this out, or they removed it since")
            ->assertSuccessful();

        expect(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
    });

    it('imports users the model\'s global scopes hide, so a restored user keeps their factors', function () {
        Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
        config(['auth.providers.users.model' => SoftDeletingUser::class]);
        passkeysTable();
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_confirmed_at' => now(),
            'deleted_at' => now(),
        ]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', ...passkeyRow($this->user)]);

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        expect(Authenticator::pluck('factor')->all())->toEqualCanonicalizing(['totp', 'passkey']);

        DB::table('users')->update(['deleted_at' => null]);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('imports laravel passkeys so they keep working', function () {
        $key = new VirtualAuthenticator;

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options), 'name' => 'MacBook']);
        $this->post('/logout');

        // Pretend that passkey was made by laravel/passkeys instead.
        $made = Authenticator::where('factor', 'passkey')->sole();
        passkeysTable();
        DB::table('passkeys')->insert([
            'user_id' => $this->user->id,
            'name' => 'MacBook',
            'credential_id' => $made->credential_id,
            'credential' => $made->public_key,
            'created_at' => now(),
        ]);
        Authenticator::query()->delete();

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');

        expect($this->user->keyring->refresh()->of('passkey')->first()->name)->toBe('MacBook');
    });
});

it('prunes old devices, email changes, security events and ended sessions', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    $old = Keyring::deviceModel()::make(['token_hash' => 'a', 'revoked_at' => now()->subDays(31)]);
    $old->authenticatable()->associate($user)->save();
    $current = Keyring::deviceModel()::make(['token_hash' => 'b']);
    $current->authenticatable()->associate($user)->save();

    $change = function (array $attributes) use ($user): PendingChange {
        $change = new PendingChange(['attribute' => 'email', 'value' => 'new@example.com', 'confirm_token' => 'c', 'revert_token' => 'r', 'expires_at' => now()->addDay(), ...$attributes]);
        $change->authenticatable()->associate($user)->save();

        return $change;
    };
    $ended = [
        $change(['expires_at' => now()->subDays(31)]),
        $change(['cancelled_at' => now()->subDays(31)]),
        $change(['reverted_at' => now()->subDays(31)]),
        $change(['applied_at' => now()->subDays(40), 'revertable_until' => now()->subDays(31)]),
    ];
    $kept = [
        $change([]),
        $change(['expires_at' => now()->subDay()]),
        $change(['applied_at' => now()->subDays(40), 'expires_at' => now()->subDays(40), 'revertable_until' => now()->subDay()]),
    ];

    $event = fn (int $daysAgo) => SecurityEvent::query()->forceCreate([
        'authenticatable_type' => $user->getMorphClass(),
        'authenticatable_id' => $user->id,
        'type' => 'signed_in',
        'created_at' => now()->subDays($daysAgo),
    ]);
    $event(181);
    $recent = $event(1);

    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('ended', (string) $user->id, 'web', null, Assurance::AAL1, null, null, 0, 0, now()->subMinute()->getTimestamp()));
    $registry->save(new RegisteredSession('live', (string) $user->id, 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addDay()->getTimestamp()));

    $this->artisan('keyring:prune')->assertSuccessful();

    expect(Keyring::deviceModel()::pluck('id')->all())->toBe([$current->id])
        ->and(PendingChange::pluck('id')->sort()->values()->all())->toBe(collect($kept)->pluck('id')->sort()->values()->all())
        ->and(SecurityEvent::pluck('id')->all())->toBe([$recent->id])
        ->and($registry->find('ended'))->toBeNull()
        ->and($registry->find('live'))->not->toBeNull();
});

it('schedules the prune itself, every day, so nothing is kept because a line was left out', function () {
    $pruning = collect(app(Schedule::class)->events())->filter(fn (Event $event) => str_contains((string) $event->command, 'keyring:prune'));

    expect($pruning)->toHaveCount(1)
        ->and($pruning->first()->expression)->toBe('0 3 * * *');

    // The scheduled command is the one that prunes.
    $this->artisan('schedule:list')->expectsOutputToContain('keyring:prune')->assertSuccessful();
});

it('lets the app move the daily prune, or schedule it for itself', function (?string $at, array $expressions) {
    config(['keyring.prune_at' => $at]);
    app()->forgetInstance(Schedule::class);

    expect(collect(app(Schedule::class)->events())
        ->filter(fn (Event $event) => str_contains((string) $event->command, 'keyring:prune'))
        ->map(fn (Event $event) => $event->expression)->values()->all())->toBe($expressions);
})->with([
    'another time' => ['01:30', ['30 1 * * *']],
    'not at all' => [null, []],
]);

it('describes the setup in artisan about', function () {
    $this->artisan('about', ['--only' => 'keyring'])
        ->expectsOutputToContain('password, passkey, totp, recovery')
        ->expectsOutputToContain('registration, reset-passwords, email-verification')
        ->assertSuccessful();
});

it('publishes a provider that boots, with everything picked', function () {
    // The stub as a whole; keyring:install removes what isn't picked.
    new KeyringServiceProvider($this->app)->boot();

    expect(app(UpdatesUserPasswords::class))->toBeInstanceOf(UpdateUserPassword::class)
        ->and(app(ResetsUserPasswords::class))->toBeInstanceOf(ResetUserPassword::class)
        ->and(app(ValidatesEmailChanges::class))->toBeInstanceOf(ValidateEmailChange::class)
        ->and(Keyring::registered()->keys()->all())->toBe(['password', 'totp', 'recovery', 'passkey', 'security-key', 'email-code']);
});
