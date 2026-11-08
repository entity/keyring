import { router, useForm } from '@inertiajs/react'
import { useCallback, useEffect, useRef, useState, type ComponentType } from 'react'
import { json } from './http'
import { routes } from './routes'
import type { AuthenticatorSummary, ChallengeProps } from './types'
import { getCredential, supportsAutofill, supportsWebAuthn } from './webauthn'

export * from './index'

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
  const form = useForm<Record<string, any>>({ code: '', password: '', trust: false })

  const submit = useCallback((data: Record<string, unknown> = {}) => {
    form.transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
    form.post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
  }, [form, props.purpose, props.factor, props.authenticator.id])

  const switchTo = useCallback((option: AuthenticatorSummary) => {
    router.get(routes.challenge(props.purpose, option.factor), option.id ? { authenticator: option.id } : {})
  }, [props.purpose])

  const send = useCallback(() => {
    router.post(routes.send(props.purpose, props.factor), { authenticator: props.authenticator.id }, { preserveScroll: true })
  }, [props.purpose, props.factor, props.authenticator.id])

  /** Run the WebAuthn ceremony for passkeys and security keys, then submit. */
  const useKey = useCallback(async () => {
    form.clearErrors()

    try {
      submit({ credential: await getCredential(props.challenge.options) })
    } catch (error) {
      form.setError('credential', error instanceof Error ? error.message : String(error))
    }
  }, [form, submit, props.challenge])

  return { form, props, Component: factors[props.factor], submit, switchTo, send, useKey, alternatives: props.alternatives }
}

/**
 * Sign in with a passkey, without a username. With `autofill`, passkeys are
 * offered in the email field's autofill (give it autoComplete="username webauthn").
 */
export function usePasskeyLogin({ autofill = false, factor = 'passkey', remember = false }: { autofill?: boolean, factor?: string, remember?: boolean } = {}) {
  const [supported, setSupported] = useState(false)
  const [processing, setProcessing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const controller = useRef<AbortController | null>(null)

  const run = useCallback(async (conditional: boolean) => {
    controller.current?.abort()
    controller.current = new AbortController()
    setError(null)
    setProcessing(!conditional)

    try {
      const options = await json('GET', routes.loginOptions(factor))
      const credential = await getCredential(options, { autofill: conditional, signal: controller.current.signal })

      router.post(routes.loginWith(factor), { credential, remember }, {
        onError: errors => setError(Object.values(errors)[0] ?? null),
        onFinish: () => setProcessing(false),
      })
    } catch (caught) {
      setProcessing(false)

      // Autofill gives up quietly (no passkeys, or the user typed instead), so
      // only an explicit "Sign in with a passkey" shows an error.
      if (!conditional && !(caught instanceof DOMException && caught.name === 'AbortError')) {
        setError(caught instanceof Error ? caught.message : String(caught))
      }
    }
  }, [factor, remember])

  useEffect(() => {
    setSupported(supportsWebAuthn())

    if (autofill) {
      supportsAutofill().then(available => {
        if (available) {
          run(true)
        }
      })
    }

    return () => controller.current?.abort()
  }, [autofill, run])

  return { supported, processing, error, signIn: () => run(false) }
}
