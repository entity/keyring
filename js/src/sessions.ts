import { json } from './http.js'
import { routes } from './routes.js'
import type { Session } from './types.js'

/**
 * Everywhere the user is signed in, most recently active first.
 */
export async function listSessions(): Promise<Session[]> {
  return (await json<{ sessions: Session[] }>('GET', routes.sessions())).sessions
}

/**
 * End one session by its handle. Ending the current one signs the user out,
 * so send them to the login page afterwards.
 */
export function endSession(id: string) {
  return json('DELETE', routes.session(id))
}

/**
 * Sign out everywhere except here.
 */
export function endOtherSessions() {
  return json('DELETE', routes.sessions())
}
