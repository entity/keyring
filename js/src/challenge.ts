import { router } from '@inertiajs/core'
import { json } from './http'
import { routes } from './routes'
import type { AuthenticatorSummary, ChallengeProps } from './types'
import { getCredential } from './webauthn'

/**
 * The framework-free half of the challenge page and passkey sign in. The
 * Vue and React bindings only add state on top.
 */

/** The fields every challenge form starts with. */
export const challengeFields = () => ({ code: '', password: '', trust: false })

/** Show another of the user's authenticators ("try another way"). */
export function switchTo(props: ChallengeProps, option: AuthenticatorSummary): void {
  router.get(routes.challenge(props.purpose, option.factor), option.id ? { authenticator: option.id } : {})
}

/** Send a code, for factors that send one. */
export function sendCode(props: ChallengeProps): void {
  router.post(routes.send(props.purpose, props.factor), { authenticator: props.authenticator.id }, { preserveScroll: true })
}

/** Run the browser prompt for the challenge's passkey or security key. */
export function keyCredential(props: ChallengeProps): Promise<Record<string, any>> {
  return getCredential(props.challenge.options)
}

/** Fetch usernameless options and run the browser prompt (or autofill). */
export async function passkeyCredential(factor: string, options: { autofill?: boolean, signal?: AbortSignal } = {}): Promise<Record<string, any>> {
  return getCredential(await json('GET', routes.loginOptions(factor)), options)
}

/** Sign in with a credential from passkeyCredential(). */
export function signInWith(factor: string, credential: Record<string, any>, remember: boolean, callbacks: { onError: (message: string | null) => void, onFinish: () => void }): void {
  router.post(routes.loginWith(factor), { credential, remember }, {
    onError: errors => callbacks.onError(Object.values(errors)[0] ?? null),
    onFinish: callbacks.onFinish,
  })
}

/** The user closed the prompt, or a newer request replaced this one. */
export function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
