# Frontend

- [Introduction](#introduction)
- [Building the Pages](#building-the-pages)
- [The Challenge Page](#the-challenge-page)
    - [Vue](#vue)
    - [React](#react)
    - [Factor Components](#factor-components)
- [Signing In With a Passkey](#signing-in-with-a-passkey)
- [Challenge Helpers Without Vue or React](#challenge-helpers-without-vue-or-react)
- [Managing Authenticators](#managing-authenticators)
- [Handling Step-Up in JavaScript](#handling-step-up-in-javascript)
- [JSON Requests](#json-requests)
- [WebAuthn Helpers](#webauthn-helpers)
- [Changing Routes](#changing-routes)
- [Flash Messages and Alerts](#flash-messages-and-alerts)
- [Without Inertia](#without-inertia)

## Introduction

Keyring is headless, like Fortify. It renders [pages](sign-in-flow.md#pages) with props and answers JSON requests, and your app owns every page. `@entity/keyring` is a small browser package that does the fiddly parts: WebAuthn, enrollment, and Vue and React bindings for Inertia v3.

```bash
npm install @entity/keyring
```

> `@entity/keyring` isn't on npm yet. Until the first release, build it from the Composer package and install it from there:
>
> ```bash
> (cd vendor/entity/keyring/js && npm install && npm run build)
> npm install ./vendor/entity/keyring/js
> ```

It's plain ES modules, so it works with any bundler. The main entry point has no dependencies, so a Blade app without a bundler can copy its `dist` folder into `public/` and import it from a `<script type="module">`. It has four entry points:

| Import | Contains |
|---|---|
| `@entity/keyring` | WebAuthn helpers, enrollment helpers, `json()`, routes and types. No framework code. |
| `@entity/keyring/inertia` | The [challenge helpers](#challenge-helpers-without-vue-or-react), for Inertia with any framework. |
| `@entity/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@entity/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

## Building the Pages

Keyring renders the components `auth/login`, `auth/challenge` and so on. [Pages](sign-in-flow.md#pages) lists each one and its props. Most are plain forms posting to Keyring's routes. Two need more:

- **The challenge page** (and `confirm`, for step-up) shows whichever factor comes next. [`useChallenge()`](#the-challenge-page) does the work.
- **The login page** can offer passkeys, with [`usePasskeyLogin()`](#signing-in-with-a-passkey).

Settings pages for authenticators, devices and the email address are yours too, built on the [helpers below](#managing-authenticators) and the JSON routes. The [example app](https://github.com/entity/keyring-example) has every page, in React with the Laravel starter kit's components, if you'd like a reference.

## The Challenge Page

The `challenge` page (and `confirm`) receives the [challenge props](sign-in-flow.md#page-props). `useChallenge()` turns them into what the page needs: the component for the current factor, a form, "try another way" and submitting.

Give it a map of factor keys to components, for example in `resources/js/keyring/factors.ts`:

```ts
import { defineAsyncComponent } from 'vue'

export default {
  'password': defineAsyncComponent(() => import('./factors/Password.vue')),
  'totp': defineAsyncComponent(() => import('./factors/Code.vue')),
  'email-code': defineAsyncComponent(() => import('./factors/Code.vue')),
  'recovery': defineAsyncComponent(() => import('./factors/Code.vue')),
  'passkey': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
  'security-key': defineAsyncComponent(() => import('./factors/SecurityKey.vue')),
}
```

Adding a factor on the server means adding one line here. In React, use `lazy()` and a `<Suspense>` boundary instead.

### Vue

```vue
<script setup lang="ts">
import { useChallenge, type ChallengeProps } from '@entity/keyring/vue'
import factors from '../../keyring/factors'

const props = defineProps<ChallengeProps>()
const challenge = useChallenge(props, factors)
</script>

<template>
  <component :is="challenge.component" :key="`${props.factor}:${props.authenticator.id}`" :challenge="challenge" />

  <label v-if="props.canTrustDevice">
    <input v-model="challenge.form.trust" type="checkbox"> Don't ask again on this device
  </label>

  <button v-for="option in props.alternatives" :key="`${option.factor}:${option.id}`" @click="challenge.switchTo(option)">
    {{ option.name }}
  </button>
</template>
```

`useChallenge(props, factors)` returns a reactive object, typed `Challenge`:

| | |
|---|---|
| `form` | An Inertia form with `code`, `password` and `trust`. |
| `props` | The page props you passed in. |
| `component` | The component for `props.factor`, or `undefined` when the map has none. |
| `submit(data?)` | Posts the form, plus `data` and the authenticator ID, to the verify route. Clears `code` and `password` afterwards. |
| `switchTo(option)` | Visits the challenge page for one of `props.alternatives`. |
| `send()` | Asks the server to send a code, for factors that send one. |
| `verifyKey()` | Runs the WebAuthn ceremony with `props.challenge.options` and submits the result. Calling it again while the prompt is open replaces that prompt. Closing the prompt does nothing; other browser errors are set on `form.errors.credential`. |
| `alternatives` | `props.alternatives`. |

Factor components receive `challenge`, and read the page from `challenge.props`.

When a factor has no component in the map, `component` is `undefined`. A good fallback is your security key component when the challenge has WebAuthn `options`, otherwise your code component.

### React

```tsx
import { useChallenge, type ChallengeProps } from '@entity/keyring/react'
import { Suspense } from 'react'
import factors from '../../keyring/factors'

export default function ChallengePage(props: ChallengeProps) {
  const challenge = useChallenge(props, factors)
  const { Component, form } = challenge

  return (
    <>
      <Suspense fallback={null}>
        {Component && <Component key={`${props.factor}:${props.authenticator.id}`} challenge={challenge} />}
      </Suspense>

      {props.canTrustDevice && (
        <label>
          <input type="checkbox" checked={form.data.trust} onChange={e => form.setData('trust', e.target.checked)} />
          Don't ask again on this device
        </label>
      )}

      {props.alternatives.map(option => (
        <button key={`${option.factor}:${option.id}`} onClick={() => challenge.switchTo(option)}>{option.name}</button>
      ))}
    </>
  )
}
```

The React hook returns the same as Vue's, except `Component` (capitalised) instead of `component`. Factor components receive `challenge` (typed `Challenge`) the same way.

### Factor Components

A factor component shows the right input and calls the challenge's methods. Factors that send codes include `sent` in their challenge props, so a component can tell whether to show a "send code" button first. A minimal code factor in Vue:

```vue
<script setup lang="ts">
import type { Challenge } from '@entity/keyring/vue'

const { challenge } = defineProps<{ challenge: Challenge }>()
</script>

<template>
  <button v-if="'sent' in challenge.props.challenge && !challenge.props.challenge.sent" @click="challenge.send()">Send code</button>

  <form v-else @submit.prevent="challenge.submit()">
    <input v-model="challenge.form.code" autocomplete="one-time-code" inputmode="numeric">
    <p v-if="challenge.form.errors.code">{{ challenge.form.errors.code }}</p>
    <button :disabled="challenge.form.processing">Verify</button>
  </form>
</template>
```

A security key component usually calls `challenge.verifyKey()` as soon as it mounts, with a "try again" button in case the user dismisses the browser prompt. Under React's StrictMode, guard the call with a ref so the prompt opens once.

## Signing In With a Passkey

`usePasskeyLogin()` runs a [usernameless passkey sign in](passkeys.md#signing-in-without-a-username): it fetches the options, asks the browser, and posts the result.

```vue
<script setup lang="ts">
import { usePasskeyLogin } from '@entity/keyring/vue'
import { useForm } from '@inertiajs/vue3'

const form = useForm({ email: '', password: '', remember: false })
const { supported, processing, error, signIn } = usePasskeyLogin({ autofill: true, remember: () => form.remember })
</script>

<template>
  <input v-model="form.email" type="email" autocomplete="username webauthn">

  <button v-if="supported" :disabled="processing" @click="signIn()">Sign in with a passkey</button>
  <p v-if="error">{{ error }}</p>
</template>
```

| Option | |
|---|---|
| `autofill` | Also offer passkeys in the email field's autofill, when the browser supports it. The field needs `autocomplete="username webauthn"`. |
| `factor` | The factor key, `passkey` by default. |
| `remember` | A function returning whether "remember me" is ticked, read when the passkey is used. The same in Vue and React, for example `remember: () => form.data.remember` in React. |

It returns `supported` (whether the browser has WebAuthn), `processing`, `error` and `signIn()`. In Vue the first three are refs. The autofill request is cancelled when the component unmounts. Starting a new sign in cancels the one in progress, and only the newest one updates `processing` and `error`. `processing` is also true while a passkey picked from autofill is being checked. Closing the prompt isn't an error. After an explicit sign in that didn't work, the email field offers passkeys again.

## Challenge Helpers Without Vue or React

The Vue and React bindings are thin layers over these helpers, exported from `@entity/keyring/inertia` (and re-exported by the Vue and React entries). Use them to build the challenge page or passkey sign in with another framework. They post with Inertia's router (`@inertiajs/core`).

| Function | Does |
|---|---|
| `challengeFields()` | The fields a challenge form starts with: `code`, `password` and `trust`. |
| `switchTo(props, option)` | Visits the challenge page for one of `props.alternatives`. |
| `sendCode(props)` | Asks the server to send a code for the current authenticator. |
| `keyCredential(props, signal?)` | Runs the browser prompt with `props.challenge.options` and resolves to the credential to post as `credential`. |
| `keyPrompt()` | Makes a prompt function for a challenge page: `await prompt(props)` resolves to the credential, or `null` when the user closed the prompt or a newer call replaced it. |
| `passkeyCredential(factor, { autofill?, signal? })` | Fetches the usernameless options and runs the prompt (or autofill). |
| `signInWith(factor, credential, remember, { onError, onFinish })` | Posts a credential from `passkeyCredential()` to sign in. `onError` gets the first error message. |
| `passkeyLogin(options, onChange)` | The state behind `usePasskeyLogin()`: call `start()` once mounted, `signIn()` for the button and `stop()` when unmounting. `onChange` gets `{ processing, error }`. |
| `isAbort(error)` | Whether the error means the user closed the prompt (or it timed out), or a newer request replaced it. Browsers report those as `NotAllowedError`, which they also throw when WebAuthn isn't allowed at all, such as in a cross-origin iframe without the `publickey-credentials-get` permission. If a prompt never appears, check that first. |
| `errorMessage(error)` | A readable message for any thrown value. |

```ts
import { errorMessage, isAbort, passkeyCredential, signInWith } from '@entity/keyring/inertia'

try {
  const credential = await passkeyCredential('passkey')
  signInWith('passkey', credential, false, { onError: showError, onFinish: () => {} })
} catch (error) {
  if (!isAbort(error)) showError(errorMessage(error))
}
```

## Managing Authenticators

The enrollment helpers call the [authenticator routes](authenticators.md) with JSON:

```ts
import { beginEnrollment, confirmEnrollment, enroll, makeDefault, removeAuthenticator, renameAuthenticator } from '@entity/keyring'

// One step for factors that need no input in between.
const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop' })
const { enrollment } = await enroll('recovery')   // enrollment.codes holds the new codes

// Two steps for authenticator apps and email codes.
const started = await beginEnrollment('totp', { name: 'Work phone' })
showQrCode(started.enrollment.qr)
const added = await confirmEnrollment('totp', started.enrollment, { code })

await renameAuthenticator(added.authenticator.id, 'Personal phone')
await makeDefault(added.authenticator.id)
await removeAuthenticator(added.authenticator.id)
```

| Function | Does |
|---|---|
| `beginEnrollment(factor, data?)` | `POST /user/authenticators/{factor}`. Resolves to `{ factor, enrollment }`. |
| `confirmEnrollment(factor, enrollment, data?)` | `POST /user/authenticators/{factor}/confirm`. For `passkey` and `security-key`, runs the browser ceremony first; if the server rejects the response, the challenge is spent, so start again with `beginEnrollment()`. Resolves to `{ authenticator, recoveryCodes? }`. |
| `enroll(factor, data?)` | Both, one after the other. `data` goes to both requests. |
| `renameAuthenticator(id, name)` | `PATCH` with `name`. |
| `makeDefault(id)` | `PATCH` with `default: true`. |
| `removeAuthenticator(id, password?)` | `DELETE`. Removing the user's last second factor also needs their password. |
| `isWebAuthn(enrollment)` | Whether `confirmEnrollment()` runs the browser ceremony: true when the server sent WebAuthn creation options, whatever the factor's key. |

If `recoveryCodes` comes back, show the codes and ask the user to save them.

## Handling Step-Up in JavaScript

The authenticator routes need a [fresh verification](step-up.md#fresh-verification). When the user doesn't have one, a JSON request fails with `423` and a `redirect` to the confirm page. The helpers throw a `KeyringRequestError` with that status:

```ts
import { KeyringRequestError, enroll } from '@entity/keyring'
import { router } from '@inertiajs/vue3'

try {
  await enroll('passkey')
} catch (error) {
  if (error instanceof KeyringRequestError && error.status === 423) {
    router.visit(error.data.redirect)
    return
  }

  throw error
}
```

After a JSON `423`, Keyring remembers the page that made the call (from the `Referer` header), so once they confirm they come back to it. Without a `Referer`, Laravel uses the last page it saw in the session. You can also protect the page's own `GET` route with `keyring.fresh`. Then step-up happens when the page loads, and the JSON calls on it pass while the verification is fresh:

```php
Route::get('/settings/security', SecuritySettingsController::class)
    ->middleware(['auth', 'keyring.fresh:15m']);
```

Use a window no longer than the one in `changes_middleware`, so the page doesn't outlive the routes it calls.

The same applies to any of your own routes behind `keyring:aal2` or `keyring.fresh` that you call with `fetch` or `json()`.

## JSON Requests

`json(method, url, body?)` is the small `fetch` wrapper the helpers use. It sends `Accept: application/json`, `X-Requested-With` and Laravel's `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`, so Keyring answers with JSON and CSRF protection passes. Use it for Keyring's other JSON routes:

```ts
import { json } from '@entity/keyring'

const { devices } = await json('GET', '/user/devices')
await json('DELETE', '/user/devices')        // sign out everywhere else
const { pending } = await json('GET', '/user/email')
await json('PUT', '/user/password', { current_password, password, password_confirmation })
```

On a non-2xx response it throws a `KeyringRequestError` with `status`, `message`, `errors` (Laravel's validation errors) and `data` (the whole body).

## WebAuthn Helpers

For building your own flows:

| Function | |
|---|---|
| `supportsWebAuthn()` | Whether the browser has WebAuthn. |
| `supportsAutofill()` | Whether it can offer passkeys in autofill. |
| `createCredential(options)` | Runs `navigator.credentials.create()` with Keyring's JSON options and returns the result as JSON for the server. |
| `getCredential(options, { autofill?, signal? })` | The same for `navigator.credentials.get()`. |
| `toBase64Url(buffer)`, `fromBase64Url(value)` | Encoding helpers. |

They use the browser's built-in JSON parsing when it exists, and convert by hand when it doesn't.

## Changing Routes

The helpers use Keyring's default paths. If you changed the `prefix` option, tell them once at startup:

```ts
import { configureRoutes } from '@entity/keyring'

configureRoutes({ prefix: 'account' })
```

If you registered the routes yourself, override the ones you moved:

```ts
configureRoutes({
  enroll: factor => `/account/authenticators/${factor}`,
  confirmEnrollment: factor => `/account/authenticators/${factor}/confirm`,
  authenticator: id => `/account/authenticators/${id}`,
})
```

The keys are `prefix`, `login`, `loginOptions`, `loginWith`, `challenge`, `verify`, `send`, `challengeBase`, `enroll`, `confirmEnrollment` and `authenticator`. `challengeBase(purpose)` is the prefix the challenge routes share (`/login/challenge` for `login`, `/confirm` for `confirm`), so changing it moves all three. An override is used as written, without the `prefix`:

```ts
configureRoutes({
  challengeBase: purpose => purpose === 'login' ? '/account/login/challenge' : '/account/confirm',
})
```

Update any paths your own pages link to directly, such as `/login` or `/register`.

## Flash Messages and Alerts

Keyring's non-JSON responses flash a `status` slug to the session (JSON responses include it as `status`, with a readable `message`), such as `code-sent`, `password-updated`, `device-revoked` or `email-change-requested`. Extra data, such as new recovery codes, is flashed as `keyring.result`. See [Status Responses](sign-in-flow.md#status-responses).

Share them through your Inertia middleware alongside the ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts). `Keyring::statusMessage()` translates a slug from `keyring::status.*`, and gives `null` for anything else:

```php
use Keyring\Facades\Keyring;

public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'status' => fn () => $request->session()->get('status'),
        'statusMessage' => fn () => Keyring::statusMessage($request->session()->get('status')),
        'keyringResult' => fn () => $request->session()->get('keyring.result'),
        'keyringAlerts' => fn () => $request->session()->get('keyring.alerts', []),
    ];
}
```

The `login`, `forgot-password` and `verify-email` pages already receive the translated message as their `status` prop.

## Without Inertia

Without Inertia, Keyring renders Blade views named `auth.login`, `auth.challenge` and so on, with the props as view data. Write them yourself, or point pages anywhere with [`Keyring::page()`](sign-in-flow.md#pages). The browser package's WebAuthn and enrollment helpers work without Inertia. The challenge helpers and the `vue` and `react` entry points need it.
