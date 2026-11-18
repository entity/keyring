import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { isAbort, keyPrompt, passkeyCredential, passkeyLogin } from '../src/inertia'
import { cancelled, fakeBrowser, tick } from './hooks'

// The browser and Inertia's router, as the stand-ins in hooks.ts.
let browser: ReturnType<typeof fakeBrowser>

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
const challenge = { challenge: { options: {} } } as any

beforeEach(() => {
  browser = fakeBrowser()
})

afterEach(() => {
  browser.restore()
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
    expect(browser.prompts[0].signal?.aborted).toBe(true)

    // The new prompt opens once the browser has let go of the old one.
    await tick()
    browser.prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toEqual({ id: 'key' })
  })

  test('waits for the browser to let go of the prompt it replaces', async () => {
    browser.letsGoAfter = 10
    const prompt = keyPrompt()

    const first = prompt(challenge)
    const second = prompt(challenge)
    await wait(30)

    expect(browser.refused).toBe(0)
    expect(browser.prompts).toHaveLength(2)

    browser.prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toEqual({ id: 'key' })
  })

  test('only prompts for the newest of several calls made while it waits', async () => {
    browser.letsGoAfter = 10
    const prompt = keyPrompt()

    const first = prompt(challenge)
    const second = prompt(challenge)
    const third = prompt(challenge)
    await wait(30)

    expect(browser.refused).toBe(0)
    expect(browser.prompts).toHaveLength(2)

    browser.prompts[1].resolve({ id: 'key' })

    expect(await first).toBeNull()
    expect(await second).toBeNull()
    expect(await third).toEqual({ id: 'key' })
  })

  test('resolves to null when the user closes the prompt, and throws real failures', async () => {
    const prompt = keyPrompt()

    const closed = prompt(challenge)
    browser.prompts[0].reject(cancelled())
    expect(await closed).toBeNull()

    const failed = prompt(challenge)
    browser.prompts[1].reject(new DOMException('Bad key', 'InvalidStateError'))
    await expect(failed).rejects.toThrow('Bad key')
  })
})

describe('passkeyLogin', () => {
  test('prompts with the options the server sends under "options"', async () => {
    const login = passkeyLogin({}, () => {})

    login.signIn()
    await tick()

    expect(browser.requested).toEqual(['/login/passkey/options'])
    expect(browser.prompts[0].options).toEqual({ challenge: 'login' })
    login.stop()
  })

  test('does not start autofill once stopped, even if support is still being checked', async () => {
    const login = passkeyLogin({ autofill: true }, () => {})

    const started = login.start()
    login.stop()
    await started
    await tick()

    expect(browser.prompts).toHaveLength(0)
  })

  test('does not prompt when the request is aborted while the options are on their way', async () => {
    const controller = new AbortController()

    const settled = passkeyCredential('passkey', { signal: controller.signal }).then(() => 'resolved', (error: DOMException) => error.name)
    controller.abort()
    await tick()

    expect(browser.requested).toEqual(['/login/passkey/options'])
    expect(browser.prompts).toHaveLength(0)
    expect(await Promise.race([settled, tick().then(() => 'still waiting')])).toBe('AbortError')
  })

  test('offers autofill again after an explicit attempt is cancelled', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))

    await login.start()
    await tick()
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true])

    login.signIn()
    await tick()
    expect(browser.prompts[0].signal?.aborted).toBe(true)

    browser.prompts[1].reject(cancelled())
    await tick()

    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true, false, true])
    expect(states.at(-1)).toEqual({ processing: false, error: null })
  })

  test('waits for the browser to let go of autofill before the button asks', async () => {
    browser.letsGoAfter = 10
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))

    await login.start()
    await tick()

    login.signIn()
    await wait(30)

    expect(browser.refused).toBe(0)
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true, false])
    expect(states.at(-1)).toEqual({ processing: true, error: null })

    browser.prompts[1].resolve({ id: 'passkey' })
    await tick()

    expect(browser.visits.map(visit => visit.method)).toEqual(['post'])
    login.stop()
  })

  test('drops a passkey autofill hands over just as the button takes over', async () => {
    browser.letsGoAfter = 10
    const login = passkeyLogin({ autofill: true }, () => {})
    await login.start()
    await tick()

    // The browser picks a passkey from autofill before it lets go of the request.
    login.signIn()
    browser.prompts[0].resolve({ id: 'autofill' })
    await tick()
    await tick()

    expect(browser.visits).toHaveLength(0)
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true, false])

    browser.prompts[1].resolve({ id: 'button' })
    await tick()

    expect(browser.visits.map(visit => visit.method)).toEqual(['post'])
    login.stop()
  })

  test('shows the server error and offers autofill again when a passkey is refused', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    login.signIn()
    await tick()
    browser.prompts[1].resolve({ id: 'passkey' })
    await tick()

    browser.visits[0].options.onError({ credential: 'That passkey is not recognised.' })
    browser.visits[0].options.onFinish()
    await tick()

    expect(states.at(-1)).toEqual({ processing: false, error: 'That passkey is not recognised.' })
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true, false, true])
  })

  test('keeps quiet when autofill fails on its own', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    browser.prompts[0].reject(cancelled())
    await tick()

    expect(browser.prompts).toHaveLength(1)
    expect(states.every(state => state.error === null)).toBe(true)
  })

  test('ignores a refused autofill sign in once an explicit one has taken over', async () => {
    const states: Array<{ processing: boolean, error: string | null }> = []
    const login = passkeyLogin({ autofill: true }, state => states.push(state))
    await login.start()
    await tick()

    // Autofill picks a passkey; while it's being checked, the user clicks the button.
    browser.prompts[0].resolve({ id: 'autofill' })
    await tick()
    login.signIn()
    await tick()

    browser.visits[0].options.onError({ credential: 'Refused.' })
    browser.visits[0].options.onFinish()

    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true, false])
    expect(browser.prompts[1].signal?.aborted).toBe(false)
    expect(states.at(-1)).toEqual({ processing: true, error: null })
  })
})
