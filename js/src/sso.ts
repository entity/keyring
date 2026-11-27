import { beginEnrollment } from './enroll.js'
import { json } from './http.js'
import { routes } from './routes.js'
import type { SsoEnrollment } from './types.js'

/**
 * Send the browser to an identity provider to sign in. Keyring's redirect
 * route answers a JSON request with the provider's URL, so this works from a
 * frontend Laravel doesn't serve too. On a login page Laravel renders, a
 * plain link to one of the `providers` prop's `url`s does the same.
 * `remember` is kept for when the provider sends the user back.
 */
export async function signInWithProvider(provider: string, { remember = false }: { remember?: boolean } = {}): Promise<void> {
  const { url } = await json<{ url: string }>('GET', `${routes.ssoRedirect(provider)}${remember ? '?remember=1' : ''}`)

  location.assign(url)
}

/**
 * Confirm a step-up with a link at an identity provider, the one the confirm
 * page offers as `authenticator`: send the browser back to the provider to
 * sign in there, asked to sign in again where its `freshness` is
 * `reauthenticate`, and otherwise a plain round trip. The provider sends the user back to Keyring, which goes on
 * to the page that asked them to confirm. On a confirm page Laravel renders,
 * a plain link to the challenge's `url` does the same.
 */
export async function confirmWithProvider(authenticator: string): Promise<void> {
  const { url } = await json<{ url: string }>('GET', routes.ssoConfirm(authenticator))

  location.assign(url)
}

/**
 * Link an account at an identity provider to the signed-in user: begin the
 * `sso` enrollment, then send the browser to the provider. Keyring finishes
 * the link when the provider sends the user back, so there's nothing to
 * confirm. A missing fresh verification throws a 423 KeyringRequestError,
 * as every enrollment does, before the browser goes anywhere.
 */
export async function linkProvider(provider: string): Promise<void> {
  const { enrollment } = await beginEnrollment('sso', { provider })

  location.assign((enrollment as SsoEnrollment).url)
}
