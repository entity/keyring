# @entity/keyring

Browser helpers for [Keyring](https://github.com/entity/keyring), factor-driven authentication for Laravel: WebAuthn ceremonies, enrollment, and Inertia bindings for the challenge page in Vue and React.

```bash
npm install @entity/keyring
```

```ts
import { enroll } from '@entity/keyring'

const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop' })
```

| Import | Contains |
|---|---|
| `@entity/keyring` | WebAuthn helpers, enrollment helpers, `json()`, routes and types. No framework code. |
| `@entity/keyring/inertia` | The challenge helpers, for Inertia with any framework. |
| `@entity/keyring/vue` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for Vue. |
| `@entity/keyring/react` | Everything above, plus `useChallenge()` and `usePasskeyLogin()` for React. |

It needs the Keyring Composer package on the server. See the [frontend documentation](https://github.com/entity/keyring/blob/main/docs/frontend.md).

## License

MIT
