import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test'
import { router } from '@inertiajs/core'
import { isAbort, keyPrompt, passkeyLogin } from '../src/inertia'
import { standIn } from './browser'

// The browser prompt, the options request and Inertia's router, as stand-ins
// the tests drive by hand. They stand in for what the browser and Inertia
// provide, not for Keyring's own modules, and are taken away after each
// test: Bun runs every file in one process, and a mock.module() made here
// would replace the module for every file that runs after this one.
type Prompt = { options: object, autofill: boolean, signal?: AbortSignal, resolve: (credential: object) => void, reject: (error: unknown) => void }

let prompts: Prompt[] = []
let autofillSupported = true

// A browser has one WebAuthn request open at a time, and takes a moment to
// let go of one that was aborted. With this set, the stand-in does too, and
// refuses a request made before then the way Chrome does.
let letsGoAfter: number | null = null
let open = 0
let refused = 0
let requested: string[] = []
let posted: Array<{ url: string, callbacks: { onError: (errors: Record<string, string>) => void, onFinish: () => void } }> = []
let restore = () => {}

// A browser with the JSON helpers, so options reach the prompt as they were
// sent and a credential comes back as the JSON the test answered with.
class FakeCredential {
  static isConditionalMediationAvailable = async () => autofillSupported
  static parseRequestOptionsFromJSON = (options: object) => options

  constructor(private json: object) {}

  toJSON() {
    return this.json
  }
}

const credentials = {
  get: ({ publicKey, mediation, signal }: { publicKey: object, mediation?: string, signal?: AbortSignal }) => new Promise((resolve, reject) => {
    if (letsGoAfter !== null && open > 0) {
      refused++

      return reject(new DOMException('A request is already pending.', 'OperationError'))
    }

    open++
    const close = <T>(settle: (value: T) => void) => (value: T) => {
      open--
      settle(value)
    }
    const aborted = close(() => reject(new DOMException('Aborted', 'AbortError')))

    prompts.push({ options: publicKey, autofill: mediation === 'conditional', signal, resolve: close((credential: object) => resolve(new FakeCredential(credential))), reject: close(reject) })
    signal?.addEventListener('abort', () => letsGoAfter === null ? aborted(undefined) : setTimeout(aborted, letsGoAfter))
  }),
}

const tick = () => new Promise(resolve => setTimeout(resolve, 0))
const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
const cancelled = () => new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
const challenge = { challenge: { options: {} } } as any

beforeEach(() => {
  prompts = []
  posted = []
  requested = []
  autofillSupported = true
  letsGoAfter = null
  open = 0
  refused = 0

  restore = standIn({
    window: globalThis,
    PublicKeyCredential: FakeCredential,
    document: { cookie: '' },
    navigator: { credentials },
    // Answers without a turn of the event loop, as the tests wait one tick.
    fetch: async (url: string) => {
      requested.push(url)

      return { ok: true, status: 200, json: async () => ({ options: { challenge: 'abc' } }) }
    },
  })

  spyOn(router, 'post').mockImplementation(((url: string, _data: object, callbacks: any) => {
    posted.push({ url, callbacks })
  }) as any)
})

afterEach(() => {
  restore()
  ;(router.post as any).mockRestore()
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
    expect(prompts[0].signal?.aborted).toBe(true)

    // The new prompt opens once the browser has let go of the old one.
    await tick()
    prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toEqual({ id: 'key' })
  })

  test('waits for the browser to let go of the prompt it replaces', async () => {
    letsGoAfter = 10
    const prompt = keyPrompt()

    const first = prompt(challenge)
    const second = prompt(challenge)
    await wait(30)

    expect(refused).toBe(0)
    expect(prompts).toHaveLength(2)

    prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toEqual({ id: 'key' })
  })

  test('only prompts for the newest of several calls made while it waits', async () => {
    letsGoAfter = 10
    const prompt = keyPrompt()

    const first = prompt(challenge)
    const second = prompt(challenge)
    const third = prompt(challenge)
    await wait(30)

    expect(refused).toBe(0)
    expect(prompts).toHaveLength(2)

    prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toBeNull()
    expect(await third).toEqual({ id: 'key' })
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
  test('prompts with the options the server sends under "options"', async () => {
    const login = passkeyLogin({}, () => {})

    login.signIn()
    await tick()

    expect(requested).toEqual(['/login/passkey/options'])
    expect(prompts[0].options).toEqual({ challenge: 'abc' })
    login.stop()
  })

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

  test('waits for the browser to let go of autofill before the button asks', async () => {
    letsGoAfter = 10
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))

    await login.start()
    await tick()

    login.signIn()
    await wait(30)

    expect(refused).toBe(0)
    expect(prompts.map(prompt => prompt.autofill)).toEqual([true, false])
    expect(states.at(-1)).toEqual({ processing: true, error: null })

    prompts[1].resolve({ id: 'passkey' })
    await tick()

    expect(posted).toHaveLength(1)
    login.stop()
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
