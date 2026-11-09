import { useForm } from '@inertiajs/react'
import { useEffect, useRef, useState, type ComponentType } from 'react'
import { challengeFields, errorMessage, keyPrompt, passkeyLogin, sendCode, switchTo, type PasskeyLoginOptions, type PasskeyLoginState } from './inertia.js'
import { routes } from './routes.js'
import type { AuthenticatorSummary, ChallengeProps } from './types.js'
import { supportsWebAuthn } from './webauthn.js'

export * from './index.js'
export * from './inertia.js'

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
  const [promptForKey] = useState(keyPrompt)

  function submit(data: Record<string, unknown> = {}) {
    form.transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
    form.post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
  }

  /** Run the passkey or security key prompt, then submit. */
  async function verifyKey() {
    form.clearErrors()

    try {
      const credential = await promptForKey(props)

      if (credential) {
        submit({ credential })
      }
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
export function usePasskeyLogin({ autofill = false, factor = 'passkey', remember = () => false }: PasskeyLoginOptions = {}) {
  const [supported, setSupported] = useState(false)
  const [state, setState] = useState<PasskeyLoginState>({ processing: false, error: null })
  const login = useRef<ReturnType<typeof passkeyLogin> | null>(null)
  const rememberRef = useRef(remember)

  useEffect(() => {
    rememberRef.current = remember
  })

  useEffect(() => {
    setSupported(supportsWebAuthn())

    const current = (login.current = passkeyLogin({ factor, autofill, remember: () => rememberRef.current() }, setState))
    current.start()

    return () => current.stop()
  }, [autofill, factor])

  return { supported, ...state, signIn: () => login.current?.signIn() }
}
