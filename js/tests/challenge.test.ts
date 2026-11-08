import { beforeEach, describe, expect, mock, test } from 'bun:test'

// The browser prompt, the options request and Inertia's router, as stand-ins
// the tests drive by hand.
type Prompt = { autofill: boolean, signal?: AbortSignal, resolve: (credential: object) => void, reject: (error: unknown) => void }

let prompts: Prompt[] = []
let autofillSupported = true
let posted: Array<{ url: string, callbacks: { onError: (errors: Record<string, string>) => void, onFinish: () => void } }> = []

mock.module('../src/webauthn', () => ({
  supportsAutofill: async () => autofillSupported,
  getCredential: (_options: object, { autofill = false, signal }: { autofill?: boolean, signal?: AbortSignal } = {}) => new Promise((resolve, reject) => {
    prompts.push({ autofill, signal, resolve, reject })
    signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  }),
}))

mock.module('../src/http', () => ({ json: async () => ({ challenge: 'abc' }) }))

mock.module('@inertiajs/core', () => ({
  router: { post: (url: string, _data: object, callbacks: any) => posted.push({ url, callbacks }), get: () => {} },
}))

const { isAbort, keyPrompt, passkeyLogin } = await import('../src/challenge')

const tick = () => new Promise(resolve => setTimeout(resolve, 0))
const cancelled = () => new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
const challenge = { challenge: { options: {} } } as any

beforeEach(() => {
  prompts = []
  posted = []
  autofillSupported = true
})

describe('isAbort', () => {
  test('counts a closed prompt and a replaced request, but not real failures', () => {
    expect(isAbort(new DOMException('', 'AbortError'))).toBe(true)
    expect(isAbort(cancelled())).toBe(true)
    expect(isAbort(new DOMException('', 'InvalidStateError'))).toBe(false)
    expect(isAbort(new Error('nope'))).toBe(false)
  })
})

describe('keyPrompt', () => {
  test('replaces a prompt that is still open', async () => {
    const prompt = keyPrompt()

    const first = prompt(challenge)
    const second = prompt(challenge)
    prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toEqual({ id: 'key' })
    expect(prompts[0].signal?.aborted).toBe(true)
  })

  test('resolves to null when the user closes the prompt, and throws real failures', async () => {
    const prompt = keyPrompt()

    const closed = prompt(challenge)
    prompts[0].reject(cancelled())
    expect(await closed).toBeNull()

    const failed = prompt(challenge)
    prompts[1].reject(new DOMException('Bad key', 'InvalidStateError'))
    await expect(failed).rejects.toThrow('Bad key')
  })
})

describe('passkeyLogin', () => {
  test('does not start autofill once stopped, even if support is still being checked', async () => {
    const login = passkeyLogin({ autofill: true }, () => {})

    const started = login.start()
    login.stop()
    await started

    expect(prompts).toHaveLength(0)
  })

  test('offers autofill again after an explicit attempt is cancelled', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))

    await login.start()
    await tick()
    expect(prompts.map(prompt => prompt.autofill)).toEqual([true])

    login.signIn()
    await tick()
    expect(prompts[0].signal?.aborted).toBe(true)

    prompts[1].reject(cancelled())
    await tick()

    expect(prompts.map(prompt => prompt.autofill)).toEqual([true, false, true])
    expect(states.at(-1)).toEqual({ processing: false, error: null })
  })

  test('shows the server error and offers autofill again when a passkey is refused', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    login.signIn()
    await tick()
    prompts[1].resolve({ id: 'passkey' })
    await tick()

    posted[0].callbacks.onError({ credential: 'That passkey is not recognised.' })
    posted[0].callbacks.onFinish()
    await tick()

    expect(states.at(-1)).toEqual({ processing: false, error: 'That passkey is not recognised.' })
    expect(prompts.map(prompt => prompt.autofill)).toEqual([true, false, true])
  })

  test('keeps quiet when autofill fails on its own', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    prompts[0].reject(cancelled())
    await tick()

    expect(prompts).toHaveLength(1)
    expect(states.every(state => state.error === null)).toBe(true)
  })

  test('ignores a refused autofill sign in once an explicit one has taken over', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    // Autofill picks a passkey; while it's being checked, the user clicks the button.
    prompts[0].resolve({ id: 'autofill' })
    await tick()
    login.signIn()
    await tick()

    posted[0].callbacks.onError({ credential: 'Refused.' })
    posted[0].callbacks.onFinish()

    expect(prompts.map(prompt => prompt.autofill)).toEqual([true, false])
    expect(prompts[1].signal?.aborted).toBe(false)
    expect(states.at(-1)).toEqual({ processing: true, error: null })
  })
})
