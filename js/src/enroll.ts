import { json } from './http.js'
import { routes } from './routes.js'
import type { Authenticator, Enrollment } from './types.js'
import { createCredential } from './webauthn.js'

/**
 * Whether an enrollment needs the browser's WebAuthn ceremony. Decided by
 * what the server sent (creation options), so factors registered under
 * their own key work too.
 */
export function isWebAuthn(enrollment: Record<string, any>): boolean {
  return enrollment.options?.challenge !== undefined && enrollment.options?.rp !== undefined
}

/**
 * Start enrolling: returns what to show (a QR code, recovery codes...).
 */
export function beginEnrollment(factor: string, data: Record<string, unknown> = {}) {
  return json<Enrollment>('POST', routes.enroll(factor), data)
}

/**
 * Finish enrolling. WebAuthn factors run the browser ceremony for you.
 */
export async function confirmEnrollment(factor: string, enrollment: Record<string, any>, data: Record<string, unknown> = {}) {
  const payload = isWebAuthn(enrollment)
    ? { ...data, credential: await createCredential(enrollment.options) }
    : data

  return json<{ authenticator: Authenticator, recoveryCodes?: string[] }>('POST', routes.confirmEnrollment(factor), payload)
}

/**
 * Begin and finish in one go, for factors that need no input in between
 * (passkeys, security keys, recovery codes).
 */
export async function enroll(factor: string, data: Record<string, unknown> = {}) {
  const { enrollment } = await beginEnrollment(factor, data)

  return { enrollment, ...(await confirmEnrollment(factor, enrollment, data)) }
}

export function renameAuthenticator(id: string, name: string) {
  return json<{ authenticator: Authenticator }>('PATCH', routes.authenticator(id), { name })
}

export function makeDefault(id: string) {
  return json<{ authenticator: Authenticator }>('PATCH', routes.authenticator(id), { default: true })
}

/**
 * Remove an authenticator. Removing the user's last second factor also needs
 * their password, so Keyring can check it's long enough on its own; without
 * it the request fails with an error on `password`. `signOutOthers` ends the
 * user's other sessions along with it.
 */
export function removeAuthenticator(id: string, password?: string, { signOutOthers }: { signOutOthers?: boolean } = {}) {
  const body = {
    ...(password !== undefined && { password }),
    ...(signOutOthers !== undefined && { sign_out_others: signOutOthers }),
  }

  return json('DELETE', routes.authenticator(id), Object.keys(body).length === 0 ? undefined : body)
}
