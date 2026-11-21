import { json } from './http.js'
import { routes } from './routes.js'
import { getCredential } from './webauthn.js'

/** Fetch usernameless options and run the browser prompt (or autofill). */
export async function passkeyCredential(factor: string, options: { autofill?: boolean, signal?: AbortSignal } = {}): Promise<Record<string, any>> {
  const login = await json<{ options: Record<string, any> }>('GET', routes.loginOptions(factor))

  // Replaced while the options were on their way: nothing to ask the browser.
  options.signal?.throwIfAborted()

  return getCredential(login.options, options)
}
