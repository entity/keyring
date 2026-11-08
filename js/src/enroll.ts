import { json } from './http'
import { routes } from './routes'
import { createCredential } from './webauthn'

const webauthnFactors = new Set(['passkey', 'security-key'])

export function isWebAuthn(factor: string): boolean {
  return webauthnFactors.has(factor)
}

/**
 * Start enrolling: returns what to show (a QR code, recovery codes...).
 */
export function beginEnrollment(factor: string, data: Record<string, unknown> = {}) {
  return json<{ factor: string, enrollment: Record<string, any> }>('POST', routes.enroll(factor), data)
}

/**
 * Finish enrolling. WebAuthn factors run the browser ceremony for you.
 */
export async function confirmEnrollment(factor: string, enrollment: Record<string, any>, data: Record<string, unknown> = {}) {
  const payload = isWebAuthn(factor)
    ? { ...data, credential: await createCredential(enrollment.options) }
    : data

  return json<{ authenticator: Record<string, any>, recoveryCodes?: string[] }>('POST', routes.confirmEnrollment(factor), payload)
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
  return json('PATCH', routes.authenticator(id), { name })
}

export function makeDefault(id: string) {
  return json('PATCH', routes.authenticator(id), { default: true })
}

export function removeAuthenticator(id: string) {
  return json('DELETE', routes.authenticator(id))
}
