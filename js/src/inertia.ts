import { router } from '@inertiajs/core'
import { passkeyCredential } from './login.js'
import { routes } from './routes.js'
import type { AuthenticatorSummary, ChallengeProps } from './types.js'
import { getCredential, isAbort, supportsAutofill } from './webauthn.js'

// These two need no Inertia, so the main entry point has them too.
export { passkeyCredential } from './login.js'
export { isAbort } from './webauthn.js'

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
export function keyCredential(props: ChallengeProps, signal?: AbortSignal): Promise<Record<string, any>> {
  return getCredential(props.challenge.options, { signal })
}

/**
 * Browsers allow one WebAuthn request at a time, and take a moment to let go
 * of one that was aborted: until then a new one is refused ("A request is
 * already pending"). So a request made while another is still open waits for
 * it to settle first, and gives up if a newer one replaced it meanwhile. With
 * none open it's made straight away, still inside the click that asked.
 */
function oneAtATime(): <T>(signal: AbortSignal, request: () => Promise<T>) => Promise<T> {
  let open: Promise<void> | null = null

  return (signal, request) => {
    const start = async () => {
      signal.throwIfAborted()

      return request()
    }

    const next = open === null ? start() : open.then(start)
    const settled: Promise<void> = next.then(() => {}, () => {}).then(() => {
      if (open === settled) {
        open = null
      }
    })

    open = settled

    return next
  }
}

/**
 * Make a key prompt for a challenge page. Browsers allow one prompt at a
 * time, so a newer call aborts the one still open and takes over. Resolves to
 * the credential, or null when the prompt was cancelled or replaced.
 */
export function keyPrompt(): (props: ChallengeProps) => Promise<Record<string, any> | null> {
  let current: AbortController | null = null
  const queue = oneAtATime()

  return async (props) => {
    current?.abort()
    const controller = (current = new AbortController())

    try {
      return await queue(controller.signal, () => keyCredential(props, controller.signal))
    } catch (error) {
      if (current !== controller || isAbort(error)) {
        return null
      }

      throw error
    }
  }
}

/** Sign in with a credential from passkeyCredential(). */
export function signInWith(factor: string, credential: Record<string, any>, remember: boolean, callbacks: { onError: (message: string | null) => void, onFinish: () => void }): void {
  router.post(routes.loginWith(factor), { credential, remember }, {
    onError: errors => callbacks.onError(Object.values(errors)[0] ?? null),
    onFinish: callbacks.onFinish,
  })
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export interface PasskeyLoginState {
  processing: boolean
  error: string | null
}

export interface PasskeyLoginOptions {
  factor?: string
  autofill?: boolean
  remember?: () => boolean
}

/**
 * A usernameless passkey sign in, without the framework: the Vue and React
 * hooks only keep its state. The newest request owns the state. Autofill
 * gives up quietly, and is offered again after an explicit attempt that
 * didn't sign in. Call start() once mounted and stop() when unmounting.
 */
export function passkeyLogin(
  { factor = 'passkey', autofill = false, remember = () => false }: PasskeyLoginOptions,
  onChange: (state: PasskeyLoginState) => void,
) {
  const state: PasskeyLoginState = { processing: false, error: null }
  let current: AbortController | null = null
  let canAutofill = false
  let stopped = false
  const queue = oneAtATime()

  function set(changes: Partial<PasskeyLoginState>): void {
    if (!stopped) {
      onChange({ ...Object.assign(state, changes) })
    }
  }

  function offerAutofill(): void {
    if (canAutofill && !stopped) {
      run(true)
    }
  }

  async function run(conditional: boolean): Promise<void> {
    current?.abort()
    const controller = (current = new AbortController())
    const isCurrent = () => current === controller

    if (!conditional) {
      set({ processing: true, error: null })
    }

    try {
      const credential = await queue(controller.signal, () => passkeyCredential(factor, { autofill: conditional, signal: controller.signal }))

      // The browser can still hand over a passkey just as a newer request
      // takes over; that one owns the state now.
      if (!isCurrent()) {
        return
      }

      // A passkey was picked (from autofill too), so it's being checked now.
      set({ processing: true, error: null })

      let refused = false

      signInWith(factor, credential, remember(), {
        onError: (message) => {
          refused = true

          if (isCurrent()) {
            set({ error: message })
          }
        },
        // Inertia calls this after onError too.
        onFinish: () => {
          if (isCurrent()) {
            set({ processing: false })

            if (refused) {
              offerAutofill()
            }
          }
        },
      })
    } catch (caught) {
      if (!isCurrent()) {
        return
      }

      set({ processing: false })

      // Only an explicit "Sign in with a passkey" shows an error, and
      // afterwards the email field offers passkeys again.
      if (!conditional) {
        set({ error: isAbort(caught) ? null : errorMessage(caught) })
        offerAutofill()
      }
    }
  }

  return {
    async start(): Promise<void> {
      set({ processing: false, error: null })
      canAutofill = autofill && await supportsAutofill()
      offerAutofill()
    },
    signIn: () => run(false),
    stop(): void {
      stopped = true
      current?.abort()
    },
  }
}
