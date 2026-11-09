import { useForm } from '@inertiajs/vue3'
import { computed, onBeforeUnmount, onMounted, reactive, ref, type Component } from 'vue'
import { challengeFields, errorMessage, keyPrompt, passkeyLogin, sendCode, switchTo, type PasskeyLoginOptions } from './challenge.js'
import { routes } from './routes.js'
import type { AuthenticatorSummary, ChallengeProps } from './types.js'
import { supportsWebAuthn } from './webauthn.js'

export * from './index.js'
export * from './challenge.js'

export type Challenge = ReturnType<typeof useChallenge>

/**
 * Everything a challenge or confirm page needs: the component for the
 * current factor, "try another way", and submitting. It's reactive, so pass
 * it straight to factor components.
 *
 * `factors` maps factor keys to components (use defineAsyncComponent to
 * load them lazily), so supporting a new factor is one line.
 */
export function useChallenge(props: ChallengeProps, factors: Record<string, Component>) {
  const form = useForm<Record<string, any>>(challengeFields())
  const promptForKey = keyPrompt()

  function submit(data: Record<string, unknown> = {}) {
    form
      .transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
      .post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
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

  return reactive({
    form,
    props,
    component: computed(() => factors[props.factor] as Component | undefined),
    alternatives: computed(() => props.alternatives),
    submit,
    verifyKey,
    switchTo: (option: AuthenticatorSummary) => switchTo(props, option),
    send: () => sendCode(props),
  })
}

/**
 * Sign in with a passkey, without a username. With `autofill`, passkeys are
 * offered in the email field's autofill (give it autocomplete="username webauthn").
 */
export function usePasskeyLogin(options: PasskeyLoginOptions = {}) {
  const supported = ref(false)
  const processing = ref(false)
  const error = ref<string | null>(null)

  const login = passkeyLogin(options, (state) => {
    processing.value = state.processing
    error.value = state.error
  })

  onMounted(() => {
    supported.value = supportsWebAuthn()
    login.start()
  })

  onBeforeUnmount(() => login.stop())

  return { supported, processing, error, signIn: login.signIn }
}
