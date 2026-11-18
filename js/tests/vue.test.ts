import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { createRenderer, effectScope, reactive } from 'vue'
import { useChallenge, usePasskeyLogin } from '../src/vue'
import { cancelled, challengeProps, fakeBrowser, tick } from './hooks'

// Inertia's own useForm, which works without a page. Nothing is replaced
// with mock.module: Bun keeps a module mock for every file that runs after.
let browser: ReturnType<typeof fakeBrowser>
let mounted: Array<() => void> = []

beforeEach(() => {
  browser = fakeBrowser()
})

// Unmount whatever a test left mounted while the stand-ins are still there.
afterEach(() => {
  try {
    mounted.forEach(unmount => unmount())
  } finally {
    mounted = []
    browser.restore()
  }
})

// A renderer that draws nothing, so onMounted and onBeforeUnmount run
// without a DOM.
const { createApp } = createRenderer<object, object>({
  createElement: () => ({}),
  createText: () => ({}),
  createComment: () => ({}),
  insert: () => {},
  remove: () => {},
  setText: () => {},
  setElementText: () => {},
  parentNode: () => null,
  nextSibling: () => null,
  patchProp: () => {},
})

function mount<T>(use: () => T) {
  let result!: T
  const app = createApp({
    setup() {
      result = use()

      return () => null
    },
  })

  app.mount({})

  let unmounted = false
  const unmount = () => {
    if (!unmounted) {
      unmounted = true
      app.unmount()
    }
  }

  mounted.push(unmount)

  return { result, unmount }
}

describe('vue useChallenge', () => {
  test('is reactive, so factor components can read it without refs', () => {
    const Code = { name: 'Code' }
    const Recovery = { name: 'Recovery' }
    const props = reactive({
      purpose: 'login',
      factor: 'totp',
      authenticator: { factor: 'totp', id: 'a1', name: 'Phone' },
      challenge: {},
      alternatives: [{ factor: 'recovery', id: 'r1', name: 'Recovery codes' }],
      canTrustDevice: true,
      expiresAt: '2026-11-08T12:00:00Z',
    }) as any

    effectScope().run(() => {
      const challenge = useChallenge(props, { totp: Code, recovery: Recovery })

      expect(challenge.component).toBe(Code)
      expect(challenge.props.authenticator.name).toBe('Phone')
      expect(challenge.form.code).toBe('')

      props.factor = 'recovery'

      expect(challenge.component).toBe(Recovery)
    })
  })

  test('posts the fields and the authenticator to the factor, then clears the secrets', () => {
    const { result: challenge } = mount(() => useChallenge(challengeProps({ purpose: 'login', factor: 'totp', authenticator: { factor: 'totp', id: 'a1', name: 'Phone' } }), {}))

    challenge.form.code = '123456'
    challenge.form.trust = true
    challenge.submit({ remember: true })

    expect(browser.visits).toHaveLength(1)
    const [visit] = browser.visits
    expect(visit.method).toBe('post')
    expect(visit.url).toBe('/login/challenge/totp')
    expect(visit.data).toEqual({ code: '123456', password: '', trust: true, remember: true, authenticator: 'a1' })
    expect(visit.options.preserveScroll).toBe(true)

    visit.options.onFinish()

    expect(challenge.form.code).toBe('')
    expect(challenge.form.trust).toBe(true)
  })

  test('prompts for the key and submits the credential', async () => {
    const { result: challenge } = mount(() => useChallenge(challengeProps(), {}))
    challenge.form.setError('credential', 'Left over from last time.')

    const verifying = challenge.verifyKey()

    expect(challenge.form.errors).toEqual({})
    expect(browser.prompts[0].options).toEqual({ challenge: 'confirm' })

    browser.prompts[0].resolve({ id: 'key' })
    await verifying

    expect(browser.visits.map(({ method, url }) => `${method} ${url}`)).toEqual(['post /confirm/security-key'])
    expect(browser.visits[0].data).toMatchObject({ credential: { id: 'key' }, authenticator: 'k1' })
  })

  test('does nothing when the user closes the prompt', async () => {
    const { result: challenge } = mount(() => useChallenge(challengeProps(), {}))

    const verifying = challenge.verifyKey()
    browser.prompts[0].reject(cancelled())
    await verifying

    expect(browser.visits).toEqual([])
    expect(challenge.form.errors).toEqual({})
  })

  test('shows a failed prompt on the credential field', async () => {
    const { result: challenge } = mount(() => useChallenge(challengeProps(), {}))

    const verifying = challenge.verifyKey()
    browser.prompts[0].reject(new DOMException('This key is not registered.', 'InvalidStateError'))
    await verifying

    expect(browser.visits).toEqual([])
    expect(challenge.form.errors).toEqual({ credential: 'This key is not registered.' })
  })

  test('shows the browser handing back no credential on the credential field', async () => {
    const { result: challenge } = mount(() => useChallenge(challengeProps(), {}))

    const verifying = challenge.verifyKey()
    browser.prompts[0].resolve(null)
    await verifying

    expect(browser.visits).toEqual([])
    expect(challenge.form.errors).toEqual({ credential: 'No passkey or security key was used.' })
  })

  test('switches to another authenticator and sends codes', () => {
    const props = challengeProps({ purpose: 'login', factor: 'email', authenticator: { factor: 'email', id: 'e1', name: 'Email' } })
    const { result: challenge } = mount(() => useChallenge(props, {}))

    challenge.switchTo(props.alternatives[0])
    challenge.switchTo(props.alternatives[1])
    challenge.send()

    expect(browser.visits.map(({ method, url, data }) => ({ method, url, data }))).toEqual([
      { method: 'get', url: '/login/challenge/recovery', data: { authenticator: 'r1' } },
      { method: 'get', url: '/login/challenge/password', data: {} },
      { method: 'post', url: '/login/challenge/email/send', data: { authenticator: 'e1' } },
    ])
    expect(browser.visits[2].options).toEqual({ preserveScroll: true })
  })
})

describe('vue usePasskeyLogin', () => {
  test('offers autofill once mounted, and lets go of it when unmounted', async () => {
    const { result: login, unmount } = mount(() => usePasskeyLogin({ autofill: true }))

    expect(login.supported.value).toBe(true)
    await tick()

    expect(browser.requested).toEqual(['/login/passkey/options'])
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true])

    unmount()

    expect(browser.prompts[0].signal?.aborted).toBe(true)
  })

  test('is not supported without webauthn', () => {
    delete (globalThis as any).PublicKeyCredential

    const { result: login } = mount(() => usePasskeyLogin())

    expect(login.supported.value).toBe(false)
  })

  test('keeps processing and the error in refs', async () => {
    const { result: login } = mount(() => usePasskeyLogin({ remember: () => true }))

    login.signIn()
    await tick()
    expect(login.processing.value).toBe(true)

    browser.prompts[0].reject(new Error('The passkey could not be read.'))
    await tick()
    expect(login.processing.value).toBe(false)
    expect(login.error.value).toBe('The passkey could not be read.')

    login.signIn()
    await tick()
    expect(login.error.value).toBeNull()

    browser.prompts[1].resolve({ id: 'passkey' })
    await tick()
    expect(browser.visits[0]).toMatchObject({ url: '/login/passkey', data: { credential: { id: 'passkey' }, remember: true } })

    browser.visits[0].options.onError({ credential: 'That passkey is not recognised.' })
    browser.visits[0].options.onFinish()
    expect(login.processing.value).toBe(false)
    expect(login.error.value).toBe('That passkey is not recognised.')
  })
})
