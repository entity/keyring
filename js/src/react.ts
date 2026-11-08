import { useForm } from '@inertiajs/react'
import { useEffect, useRef, useState, type ComponentType } from 'react'
import { challengeFields, errorMessage, isAbort, keyCredential, passkeyCredential, sendCode, signInWith, switchTo } from './challenge'
import { routes } from './routes'
import type { AuthenticatorSummary, ChallengeProps } from './types'
import { supportsAutofill, supportsWebAuthn } from './webauthn'

export * from './index'
export * from './challenge'

export type Challenge = ReturnType<typeof useChallenge>

export type FactorComponent = ComponentType<{ challenge: Challenge }>

/**
 * Everything a challenge or confirm page needs: the component for the
 * current factor, "try another way", and submitting.
 *
 * `factors` maps factor keys to components (use React.lazy to load them
 * lazily), so supporting a new factor is one line.
 */
export function useChallenge(props: ChallengeProps, factors: Record<string, FactorComponent>) {
  const form = useForm<Record<string, any>>(challengeFields())

  function submit(data: Record<string, unknown> = {}) {
    form.transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
    form.post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
  }

  /** Run the passkey or security key prompt, then submit. */
  async function verifyKey() {
    form.clearErrors()

    try {
      submit({ credential: await keyCredential(props) })
    } catch (error) {
      form.setError('credential', errorMessage(error))
    }
  }

  return {
    form,
    props,
    Component: factors[props.factor] as FactorComponent | undefined,
    alternatives: props.alternatives,
    submit,
    verifyKey,
    switchTo: (option: AuthenticatorSummary) => switchTo(props, option),
    send: () => sendCode(props),
  }
}

/**
 * Sign in with a passkey, without a username. With `autofill`, passkeys are
 * offered in the email field's autofill (give it autoComplete="username webauthn").
 */
export function usePasskeyLogin({ autofill = false, factor = 'passkey', remember = () => false }: { autofill?: boolean, factor?: string, remember?: () => boolean } = {}) {
  const [supported, setSupported] = useState(false)
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const current = useRef<AbortController | null>(null)
  const rememberRef = useRef(remember)

  useEffect(() => {
    rememberRef.current = remember
  })

  async function signIn(conditional: boolean) {
    current.current?.abort()
    const controller = (current.current = new AbortController())
    setError(null)
    setProcessing(!conditional)

    try {
      const credential = await passkeyCredential(factor, { autofill: conditional, signal: controller.signal })

      signInWith(factor, credential, rememberRef.current(), { onError: setError, onFinish: () => setProcessing(false) })
    } catch (caught) {
      // A newer request took over; it owns the state now.
      if (current.current !== controller) {
        return
      }

      setProcessing(false)

      // Autofill gives up quietly (no passkeys, or the user typed instead), so
      // only an explicit "Sign in with a passkey" shows an error.
      if (!conditional && !isAbort(caught)) {
        setError(errorMessage(caught))
      }
    }
  }

  useEffect(() => {
    let cancelled = false
    setSupported(supportsWebAuthn())

    if (autofill) {
      supportsAutofill().then(available => {
        if (available && !cancelled) {
          signIn(true)
        }
      })
    }

    return () => {
      cancelled = true
      current.current?.abort()
    }
  }, [autofill, factor])

  return { supported, processing, error, signIn: () => signIn(false) }
}
