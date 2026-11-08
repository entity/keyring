import { useForm } from '@inertiajs/vue3'
import { computed, onBeforeUnmount, onMounted, ref, type Component } from 'vue'
import { challengeFields, errorMessage, isAbort, keyCredential, passkeyCredential, sendCode, signInWith, switchTo } from './challenge'
import { routes } from './routes'
import type { AuthenticatorSummary, ChallengeProps } from './types'
import { supportsAutofill, supportsWebAuthn } from './webauthn'

export * from './index'

/**
 * Everything a challenge or confirm page needs: the component for the
 * current factor, "try another way", and submitting.
 *
 * `factors` maps factor keys to components (use defineAsyncComponent to
 * load them lazily), so supporting a new factor is one line.
 */
export function useChallenge(props: ChallengeProps, factors: Record<string, Component>) {
  const form = useForm<Record<string, any>>(challengeFields())

  function submit(data: Record<string, unknown> = {}) {
    form
      .transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
      .post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
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
    component: computed(() => factors[props.factor] as Component | undefined),
    alternatives: computed(() => props.alternatives),
    submit,
    verifyKey,
    switchTo: (option: AuthenticatorSummary) => switchTo(props, option),
    send: () => sendCode(props),
  }
}

/**
 * Sign in with a passkey, without a username. With `autofill`, passkeys are
 * offered in the email field's autofill (give it autocomplete="username webauthn").
 */
export function usePasskeyLogin({ autofill = false, factor = 'passkey', remember = () => false }: { autofill?: boolean, factor?: string, remember?: () => boolean } = {}) {
  const supported = ref(false)
  const processing = ref(false)
  const error = ref<string | null>(null)
  let current: AbortController | null = null

  async function signIn(conditional: boolean) {
    current?.abort()
    const controller = (current = new AbortController())
    error.value = null
    processing.value = !conditional

    try {
      const credential = await passkeyCredential(factor, { autofill: conditional, signal: controller.signal })

      signInWith(factor, credential, remember(), {
        onError: message => { error.value = message },
        onFinish: () => { processing.value = false },
      })
    } catch (caught) {
      // A newer request took over; it owns the state now.
      if (current !== controller) {
        return
      }

      processing.value = false

      // Autofill gives up quietly (no passkeys, or the user typed instead), so
      // only an explicit "Sign in with a passkey" shows an error.
      if (!conditional && !isAbort(caught)) {
        error.value = errorMessage(caught)
      }
    }
  }

  onMounted(async () => {
    supported.value = supportsWebAuthn()

    if (autofill && await supportsAutofill()) {
      signIn(true)
    }
  })

  onBeforeUnmount(() => current?.abort())

  return { supported, processing, error, signIn: () => signIn(false) }
}
