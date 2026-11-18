# @keyringjs/keyring

This package holds the browser side of [Keyring](https://github.com/entity/keyring), the factor-driven authentication package for Laravel. It handles the WebAuthn ceremonies for passkeys and security keys, enrollment, and Inertia bindings for the challenge page in Vue and React.

To install it, run:

```bash
npm install @keyringjs/keyring
```

For example, you may enroll a passkey like this:

```ts
import { enroll } from '@keyringjs/keyring'

const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop' })
```

The package has four entry points:

| Import | Contains |
|---|---|
| `@keyringjs/keyring` | WebAuthn helpers, enrollment and session helpers, `json()`, routes and types. No framework code. |
| `@keyringjs/keyring/inertia` | The challenge helpers, for Inertia with any framework. |
| `@keyringjs/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@keyringjs/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

The package needs the Keyring Composer package on the server. For the full details, see the [frontend documentation](https://github.com/entity/keyring/blob/main/docs/frontend.md).

## License

MIT
