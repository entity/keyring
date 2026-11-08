<?php

use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use App\Providers\KeyringServiceProvider;
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

    it('publishes a provider and the actions, and registers the provider', function () {
        $this->artisan('keyring:install')->assertSuccessful();

        expect(file_exists($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toBeTrue()
            ->and(array_map(basename(...), glob($this->sandbox.'/app/Actions/Keyring/*.php')))->toEqualCanonicalizing([
                'CreateNewUser.php', 'PasswordValidationRules.php', 'ResetUserPassword.php', 'UpdateUserPassword.php', 'ValidateEmailChange.php',
            ])
            ->and(file_get_contents($this->sandbox.'/bootstrap/providers.php'))->toContain('App\Providers\KeyringServiceProvider::class');
    });

    it('can run again without duplicating migrations or overwriting customised files', function () {
        $this->artisan('keyring:install')->assertSuccessful();
        file_put_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php', '<?php // mine');

        $this->artisan('keyring:install')->assertSuccessful();

        expect(glob(database_path('migrations/*_create_keyring_authenticators_table.php')))->toHaveCount(1)
            ->and(file_get_contents($this->sandbox.'/app/Providers/KeyringServiceProvider.php'))->toBe('<?php // mine');
    });
})->skip(fn () => getenv('TEST_TOKEN') !== false, 'Publishes into the testbench app every parallel worker shares.');

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

    it('imports fortify two factor and recovery codes, once', function () {
        $secret = app(Google2FA::class)->generateSecretKey();

        DB::table('users')->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_recovery_codes' => encrypt(json_encode(['abcde-12345', 'fghij-67890'])),
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
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'abcde-12345'])->assertRedirect('/dashboard');
    });

    it('imports unconfirmed secrets only when asked, without adding a second default', function () {
        config(['fortify.features' => ['two-factor-authentication'], 'fortify-options.two-factor-authentication' => ['confirm' => true]]);
        DB::table('users')->update(['two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey())]);
        $existing = Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->default()->create(['factor' => 'passkey']);

        $this->artisan('keyring:import', ['source' => 'fortify'])
            ->expectsOutputToContain("Skipped user {$this->user->id}: its secret was never confirmed")
            ->assertSuccessful();
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

        $this->artisan('keyring:import', ['source' => 'fortify', '--unconfirmed' => true])->assertSuccessful();

        $keyring = $this->user->keyring->refresh();
        expect($keyring->of('totp'))->toHaveCount(1)
            ->and($keyring->default()->id)->toBe($existing->id);
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
        Schema::create('passkeys', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id');
            $table->string('name');
            $table->string('credential_id');
            $table->json('credential');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
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

    it('imports users the model\'s global scopes hide, so a restored user keeps their factors', function () {
        Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
        config(['auth.providers.users.model' => SoftDeletingUser::class]);
        Schema::create('passkeys', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id');
            $table->string('name');
            $table->string('credential_id');
            $table->json('credential');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
        DB::table('users')->update([
            'two_factor_secret' => encrypt(app(Google2FA::class)->generateSecretKey()),
            'two_factor_confirmed_at' => now(),
            'deleted_at' => now(),
        ]);
        DB::table('passkeys')->insert(['user_id' => $this->user->id, 'name' => 'MacBook', 'credential_id' => 'a', 'credential' => '{"counter":0}']);

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
        Schema::create('passkeys', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id');
            $table->string('name');
            $table->string('credential_id');
            $table->json('credential');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
        DB::table('passkeys')->insert([
            'user_id' => $this->user->id,
            'name' => 'MacBook',
            'credential_id' => $made->credential_id,
            'credential' => $made->public_key,
            'created_at' => now(),
        ]);
        $made->delete();

        $this->artisan('keyring:import', ['source' => 'fortify'])->assertSuccessful();

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
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

it('describes the setup in artisan about', function () {
    $this->artisan('about', ['--only' => 'keyring'])
        ->expectsOutputToContain('password, totp, recovery')
        ->expectsOutputToContain('registration, password_reset, email_verification')
        ->assertSuccessful();
});

it('publishes a provider that boots and registers the actions', function () {
    new KeyringServiceProvider($this->app)->boot();

    expect(app(UpdatesUserPasswords::class))->toBeInstanceOf(UpdateUserPassword::class)
        ->and(app(ResetsUserPasswords::class))->toBeInstanceOf(ResetUserPassword::class)
        ->and(app(ValidatesEmailChanges::class))->toBeInstanceOf(ValidateEmailChange::class)
        ->and(Keyring::registered()->keys()->all())->toContain('passkey', 'security-key', 'email-code');
});
