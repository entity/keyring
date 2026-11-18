# @keyringjs/keyring

Browser helpers for [Keyring](https://github.com/entity/keyring), factor-driven authentication for Laravel: WebAuthn ceremonies, enrollment, and Inertia bindings for the challenge page in Vue and React.

```bash
npm install @keyringjs/keyring
```

```ts
import { enroll } from '@keyringjs/keyring'

const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop' })
```

| Import | Contains |
|---|---|
| `@keyringjs/keyring` | WebAuthn helpers, enrollment and session helpers, `json()`, routes and types. No framework code. |
| `@keyringjs/keyring/inertia` | The challenge helpers, for Inertia with any framework. |
| `@keyringjs/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@keyringjs/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

It needs the Keyring Composer package on the server. See the [frontend documentation](https://github.com/entity/keyring/blob/main/docs/frontend.md).

## License

MIT
