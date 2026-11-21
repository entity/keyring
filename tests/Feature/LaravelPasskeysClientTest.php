<?php

declare(strict_types=1);

use Illuminate\Testing\TestResponse;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Testing\VirtualAuthenticator;

// Laravel's browser client, @laravel/passkeys, pointed at the two login routes:
//
//     Passkeys.verify({ routes: { options: '/login/passkey/options', submit: '/login/passkey' } })
//
// These play the requests it makes, with the headers it sends, and read the
// answers the way it does.

beforeEach(function () {
    $this->user = taylor();
    $this->key = new VirtualAuthenticator;

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $this->key->register($options)])->assertOk();
    $this->post('/logout');
});

/**
 * The client's GET, which only says it wants JSON. It reads "options" from
 * the answer and hands them to the browser.
 *
 * @return array<string, mixed>
 */
function optionsForLaravelClient(): array
{
    $response = test()->get('/login/passkey/options', ['Accept' => 'application/json'])
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertJsonStructure(['options' => ['challenge', 'rpId', 'allowCredentials', 'userVerification']]);

    return $response->json('options');
}

/**
 * The assertion as @simplewebauthn/browser hands it to the client: an object
 * inside the JSON body, with the two members a browser adds.
 *
 * @param  array<string, mixed>  $options
 * @return array<string, mixed>
 */
function credentialFromLaravelClient(VirtualAuthenticator $key, array $options, ?string $origin = null): array
{
    return [...$key->assert($options, $origin), 'clientExtensionResults' => (object) [], 'authenticatorAttachment' => 'platform'];
}

/**
 * The client's POST: a JSON body, and the CSRF token from the page's meta tag.
 *
 * @param  array<string, mixed>  $body
 */
function postFromLaravelClient(array $body): TestResponse
{
    return test()->call('POST', '/login/passkey', server: [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_CSRF_TOKEN' => csrf_token(),
    ], content: json_encode($body, JSON_THROW_ON_ERROR));
}

it('signs in the way laravel\'s passkeys client does', function (array $rest) {
    $options = optionsForLaravelClient();

    expect($options['allowCredentials'])->toBe([])
        ->and($options['userVerification'])->toBe('required');

    postFromLaravelClient(['credential' => credentialFromLaravelClient($this->key, $options), ...$rest])
        ->assertOk()
        ->assertExactJson(['status' => 'authenticated', 'redirect' => url('/dashboard')]);

    $this->assertAuthenticatedAs($this->user);
})->with([
    'with remember, as 0.4 sends it' => [['remember' => false]],
    'with remember ticked' => [['remember' => true]],
    'without remember, as 0.2 sends it' => [[]],
]);

it('sends the client on to the challenge page when the policy asks for more', function () {
    Keyring::require(Requirement::factors(3));

    postFromLaravelClient(['credential' => credentialFromLaravelClient($this->key, optionsForLaravelClient()), 'remember' => false])
        ->assertStatus(202)
        ->assertExactJson(['status' => 'challenge', 'page' => 'challenge', 'redirect' => route('keyring.login.challenge')]);

    $this->assertGuest();
});

it('answers the client with a message when the passkey is not one it knows', function () {
    $options = optionsForLaravelClient();

    // Anything but a 2xx makes the client throw, with "message" as the error.
    postFromLaravelClient(['credential' => credentialFromLaravelClient(new VirtualAuthenticator, $options), 'remember' => false])
        ->assertUnprocessable()
        ->assertJsonPath('message', __('auth.failed'))
        ->assertJsonValidationErrors('credential')
        ->assertJsonMissingPath('redirect');

    $this->assertGuest();

    // That try spent the challenge, so the right passkey can't use it either.
    postFromLaravelClient(['credential' => credentialFromLaravelClient($this->key, $options), 'remember' => false])
        ->assertUnprocessable();

    $this->assertGuest();

    // The client fetches new options for every try.
    postFromLaravelClient(['credential' => credentialFromLaravelClient($this->key, optionsForLaravelClient()), 'remember' => false])
        ->assertOk()
        ->assertJsonPath('redirect', url('/dashboard'));

    $this->assertAuthenticatedAs($this->user);
});

it('checks what the client posts like any other response', function () {
    $options = optionsForLaravelClient();

    postFromLaravelClient(['credential' => credentialFromLaravelClient($this->key, $options, 'https://evil.example'), 'remember' => false])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('credential');

    $this->assertGuest();
});
