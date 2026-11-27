import { json } from './http.js'
import { routes } from './routes.js'

/**
 * Sign in as another user by their ID, where the server lets this user.
 * It needs a fresh second factor first: a 423 says where to confirm. Load
 * the page in full afterwards, at the `redirect` it answers with.
 */
export function impersonate(user: string | number) {
  return json<{ status: string, redirect?: string }>('POST', routes.impersonate(String(user)))
}

/**
 * Go back to your own account. Load the page in full afterwards: at the
 * `redirect` it answers with, or the login page when it answers 401 because
 * your own session had ended meanwhile.
 */
export function stopImpersonating() {
  return json<{ status: string, redirect?: string }>('DELETE', routes.stopImpersonating())
}
