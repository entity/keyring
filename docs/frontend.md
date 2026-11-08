# Frontend

- [Introduction](#introduction)
- [The Published Pages](#the-published-pages)
- [The Challenge Page](#the-challenge-page)
    - [Vue](#vue)
    - [React](#react)
    - [Factor Components](#factor-components)
- [Signing In With a Passkey](#signing-in-with-a-passkey)
- [Managing Authenticators](#managing-authenticators)
- [Handling Step-Up in JavaScript](#handling-step-up-in-javascript)
- [JSON Requests](#json-requests)
- [WebAuthn Helpers](#webauthn-helpers)
- [Changing Routes](#changing-routes)
- [Flash Messages and Alerts](#flash-messages-and-alerts)
- [Without Inertia](#without-inertia)

## Introduction

Keyring is headless. It renders [pages](sign-in-flow.md#pages) with props and answers JSON requests, and you decide how they look. Two things help:

- `keyring:install --inertia=vue` or `--inertia=react` publishes working pages you own and can restyle.
- `@entity/keyring` is a small browser package with WebAuthn helpers, enrollment helpers, and Vue and React bindings for Inertia v3.

```bash
npm install @entity/keyring
```

It has three entry points:

| Import | Contains |
|---|---|
| `@entity/keyring` | WebAuthn helpers, enrollment helpers, `json()`, routes and types. No framework code. |
| `@entity/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@entity/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

## The Published Pages

With `--inertia`, Keyring publishes:

```
resources/js/pages/auth/
    login, register, forgot-password, reset-password, verify-email,
    challenge, confirm, email-change, device-report
resources/js/keyring/
    factors.ts
    factors/Password, Code, SecurityKey
```

Inertia resolves them as `auth/login` and so on. Keyring doesn't publish settings pages for managing authenticators or devices; build those with the [helpers below](#managing-authenticators) and the JSON routes.

## The Challenge Page

The `challenge` page (and `confirm`, which renders it) receives the [challenge props](sign-in-flow.md#page-props). `useChallenge()` turns them into what the page needs: the component for the current factor, a form, "try another way" and submitting.

The factor components come from `resources/js/keyring/factors.ts`, which maps factor keys to components:

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
import { reactive } from 'vue'
import factors from '../../keyring/factors'

const props = defineProps<ChallengeProps>()
const challenge = reactive(useChallenge(props, factors))
</script>

<template>
  <component :is="challenge.component" :key="`${props.factor}:${props.authenticator.id}`" :challenge="challenge" :page="props" />

  <label v-if="props.canTrustDevice">
    <input v-model="challenge.form.trust" type="checkbox"> Don't ask again on this device
  </label>

  <button v-for="option in props.alternatives" :key="`${option.factor}:${option.id}`" @click="challenge.switchTo(option)">
    {{ option.name }}
  </button>
</template>
```

`useChallenge(props, factors)` returns:

| | |
|---|---|
| `form` | An Inertia form with `code`, `password` and `trust`. |
| `component` | The component for `props.factor` (a computed ref). |
| `submit(data?)` | Posts the form, plus `data` and the authenticator ID, to the verify route. Clears `code` and `password` afterwards. |
| `switchTo(option)` | Visits the challenge page for one of `props.alternatives`. |
| `send()` | Asks the server to send a code, for email codes. |
| `useKey()` | Runs the WebAuthn ceremony with `props.challenge.options` and submits the result. Browser errors (like the user cancelling) are set on `form.errors.credential`. |
| `alternatives` | `props.alternatives`, as a computed ref. |

The Vue factor components receive `challenge` and `page` (the page props).

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
        <Component key={`${props.factor}:${props.authenticator.id}`} challenge={challenge} />
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

The React hook returns the same as Vue's, except `Component` (capitalised) instead of `component`, plain values instead of refs, and the page props as `props`. React factor components receive only `challenge` (typed `Challenge`), and read the page from `challenge.props`.

### Factor Components

A factor component shows the right input and calls the challenge's methods. A minimal code factor in Vue:

```vue
<script setup lang="ts">
import type { ChallengeProps } from '@entity/keyring'

const { challenge, page } = defineProps<{ challenge: any, page: ChallengeProps }>()
</script>

<template>
  <button v-if="page.factor === 'email-code' && !page.challenge.sent" @click="challenge.send()">Send code</button>

  <form v-else @submit.prevent="challenge.submit()">
    <input v-model="challenge.form.code" autocomplete="one-time-code" inputmode="numeric">
    <p v-if="challenge.form.errors.code">{{ challenge.form.errors.code }}</p>
    <button :disabled="challenge.form.processing">Verify</button>
  </form>
</template>
```

The published `SecurityKey` component calls `challenge.useKey()` as soon as it mounts, with a "try again" button in case the user dismisses the browser prompt.

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
| `remember` | Whether to tick "remember me". A function in Vue, a boolean in React. |

It returns `supported` (whether the browser has WebAuthn), `processing`, `error` and `signIn()`. In Vue the first three are refs. The autofill request is cancelled when the component unmounts.

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
| `confirmEnrollment(factor, enrollment, data?)` | `POST /user/authenticators/{factor}/confirm`. For `passkey` and `security-key`, runs the browser ceremony first. Resolves to `{ authenticator, recoveryCodes? }`. |
| `enroll(factor, data?)` | Both, one after the other. `data` goes to both requests. |
| `renameAuthenticator(id, name)` | `PATCH` with `name`. |
| `makeDefault(id)` | `PATCH` with `default: true`. |
| `removeAuthenticator(id)` | `DELETE`. |
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

After a JSON `423`, Keyring doesn't know which page to send the user back to, so once they confirm they go to the intended URL from earlier in the session, or `home`. To bring users back to your security settings page, protect that page's `GET` route with `keyring.fresh` as well. Then step-up happens when the page loads, Keyring remembers the page, and the JSON calls on it pass while the verification is fresh:

```php
Route::get('/settings/security', SecuritySettingsController::class)
    ->middleware(['auth', 'keyring.fresh:15m']);
```

Use a window no longer than the one in `manage_middleware`, so the page doesn't outlive the routes it calls.

The same applies to any of your own routes behind `keyring:aal2` or `keyring.fresh` that you call with `fetch` or `json()`.

## JSON Requests

`json(method, url, body?)` is the small `fetch` wrapper the helpers use. It sends `Accept: application/json`, `X-Requested-With` and Laravel's `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`, so Keyring answers with JSON and CSRF protection passes. Use it for Keyring's other JSON routes:

```ts
import { json } from '@entity/keyring'

const { devices } = await json('GET', '/user/devices')
await json('DELETE', '/user/devices')        // sign out everywhere else
const { pending } = await json('GET', '/user/email')
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

The helpers use Keyring's default paths. If you changed the route prefix, or registered the routes yourself, override them once at startup:

```ts
import { configureRoutes } from '@entity/keyring'

configureRoutes({
  enroll: factor => `/account/authenticators/${factor}`,
  confirmEnrollment: factor => `/account/authenticators/${factor}/confirm`,
  authenticator: id => `/account/authenticators/${id}`,
})
```

The keys are `login`, `loginOptions`, `loginWith`, `challenge`, `verify`, `send`, `enroll`, `confirmEnrollment` and `authenticator`. The published pages also link to a few paths directly (`/login`, `/register`, `/forgot-password`), so update those too.

## Flash Messages and Alerts

Keyring's non-JSON responses flash a `status` to the session, such as `code-sent`, `password-updated`, `device-revoked` or `email-change-requested`. Share it through your Inertia middleware alongside the ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts):

```php
public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'status' => fn () => $request->session()->get('status'),
        'keyringAlerts' => fn () => $request->session()->get('keyring.alerts', []),
    ];
}
```

The published `login`, `forgot-password` and `verify-email` pages already receive `status` as a prop.

## Without Inertia

Without Inertia, Keyring renders Blade views named `auth.login`, `auth.challenge` and so on, with the props as view data. Write them yourself, or point pages anywhere with [`Keyring::page()`](sign-in-flow.md#pages). The browser package's WebAuthn and enrollment helpers work without Inertia; only the `vue` and `react` entry points need it.
