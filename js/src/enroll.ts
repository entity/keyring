import { json, KeyringRequestError } from './http.js'
import { routes } from './routes.js'
import type { Authenticator, Enrollment, FreezeProof, FrozenChanges, ProvableChange } from './types.js'
import { createCredential, getCredential } from './webauthn.js'

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
 * New recovery codes replace the old ones, so while the account is frozen
 * they need `proof` in `data` (see `proveWithKey()`).
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

  return json<{ authenticator: Authenticator, recoveryCodes?: string[], continue?: string }>('POST', routes.confirmEnrollment(factor), payload)
}

/**
 * Begin and finish in one go, for factors that need no input in between
 * (passkeys, security keys, recovery codes). A `proof` goes with the
 * beginning only, which the server remembers it for.
 */
export async function enroll(factor: string, data: Record<string, unknown> = {}) {
  const { enrollment } = await beginEnrollment(factor, data)
  const { proof: _, ...rest } = data

  return { enrollment, ...(await confirmEnrollment(factor, enrollment, rest)) }
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
 * user's other sessions along with it. While the account's sign-in methods
 * are frozen, removing an established one fails with a `422` whose `data`
 * holds `frozen` (see `FrozenChanges`), unless it comes with `proof` from
 * `proveWithKey()`.
 */
export function removeAuthenticator(id: string, password?: string, { signOutOthers, proof }: { signOutOthers?: boolean, proof?: FreezeProof } = {}) {
  const body = {
    ...(password !== undefined && { password }),
    ...(signOutOthers !== undefined && { sign_out_others: signOutOthers }),
    ...(proof !== undefined && { proof }),
  }

  return json('DELETE', routes.authenticator(id), Object.keys(body).length === 0 ? undefined : body)
}

/**
 * The freeze a request was refused for, or null when it was refused for
 * anything else. When `skip` names a passkey or security key factor, offer
 * "use your passkey to do this now", and send the request again with
 * `proveWithKey()`'s proof.
 */
export function frozenChanges(error: unknown): FrozenChanges | null {
  return error instanceof KeyringRequestError && error.status === 422 && error.data?.frozen ? error.data.frozen as FrozenChanges : null
}

/**
 * Prove one change with an established passkey or security key, while the
 * account's sign-in methods are frozen. Asks for a challenge issued for
 * that change alone, runs the browser's ceremony, and returns the proof
 * for the change's own request. It works once, and only for that change.
 *
 *     const proof = await proveWithKey('passkey', { action: 'remove', target: id })
 *     await removeAuthenticator(id, undefined, { proof })
 */
export async function proveWithKey(factor: string, change: ProvableChange): Promise<FreezeProof> {
  const { options } = await json<{ options: Record<string, any> }>('POST', routes.proofOptions(factor), change)

  return { factor, credential: await getCredential(options) }
}
