import { router, useForm } from '@inertiajs/vue3'
import { computed, onBeforeUnmount, onMounted, ref, type Component } from 'vue'
import { json } from './http'
import { routes } from './routes'
import type { AuthenticatorSummary, ChallengeProps } from './types'
import { getCredential, supportsAutofill, supportsWebAuthn } from './webauthn'

export * from './index'

/**
 * Everything a challenge or confirm page needs: the component for the
 * current factor, "try another way", and submitting.
 *
 * `factors` maps factor keys to components (use defineAsyncComponent to
 * load them lazily), so supporting a new factor is one line.
 */
export function useChallenge(props: ChallengeProps, factors: Record<string, Component>) {
  const form = useForm<Record<string, any>>({ code: '', password: '', trust: false })

  const component = computed(() => factors[props.factor])

  function submit(data: Record<string, unknown> = {}) {
    form
      .transform(fields => ({ ...fields, ...data, authenticator: props.authenticator.id }))
      .post(routes.verify(props.purpose, props.factor), { preserveScroll: true, onFinish: () => form.reset('code', 'password') })
  }

  function switchTo(option: AuthenticatorSummary) {
    router.get(routes.challenge(props.purpose, option.factor), option.id ? { authenticator: option.id } : {})
  }

  function send() {
    router.post(routes.send(props.purpose, props.factor), { authenticator: props.authenticator.id }, { preserveScroll: true })
  }

  /** Run the WebAuthn ceremony for passkeys and security keys, then submit. */
  async function useKey() {
    form.clearErrors()

    try {
      submit({ credential: await getCredential(props.challenge.options) })
    } catch (error) {
      form.setError('credential', error instanceof Error ? error.message : String(error))
    }
  }

  return { form, component, submit, switchTo, send, useKey, alternatives: computed(() => props.alternatives) }
}

/**
 * Sign in with a passkey, without a username. With `autofill`, passkeys are
 * offered in the email field's autofill (give it autocomplete="username webauthn").
 */
export function usePasskeyLogin({ autofill = false, factor = 'passkey', remember = () => false }: { autofill?: boolean, factor?: string, remember?: () => boolean } = {}) {
  const supported = ref(false)
  const processing = ref(false)
  const error = ref<string | null>(null)
  let controller: AbortController | null = null

  async function signIn(conditional = false) {
    controller?.abort()
    controller = new AbortController()
    error.value = null
    processing.value = !conditional

    try {
      const options = await json('GET', routes.loginOptions(factor))
      const credential = await getCredential(options, { autofill: conditional, signal: controller.signal })

      router.post(routes.loginWith(factor), { credential, remember: remember() }, {
        onError: errors => { error.value = Object.values(errors)[0] ?? null },
        onFinish: () => { processing.value = false },
      })
    } catch (caught) {
      processing.value = false

      // Autofill gives up quietly (no passkeys, or the user typed instead), so
      // only an explicit "Sign in with a passkey" shows an error.
      if (!conditional && !(caught instanceof DOMException && caught.name === 'AbortError')) {
        error.value = caught instanceof Error ? caught.message : String(caught)
      }
    }
  }

  onMounted(async () => {
    supported.value = supportsWebAuthn()

    if (autofill && await supportsAutofill()) {
      signIn(true)
    }
  })

  onBeforeUnmount(() => controller?.abort())

  return { supported, processing, error, signIn: () => signIn(false) }
}
