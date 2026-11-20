import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { act, createElement } from 'react'
import { createRoot } from 'react-dom/client'
import { useChallenge, usePasskeyLogin } from '../src/react'
import { cancelled, challengeProps, fakeBrowser, tick } from './hooks'

// Inertia's own useForm, rendered with react-dom. The hooks render nothing,
// so react-dom only needs the little of a DOM it touches when mounting a
// root: an element to mount in, a document to listen on and the iframe
// class it checks the focused element against. If a react-dom upgrade
// breaks every test here, it probably reads one more property: add it below.
const document = { nodeType: 9, cookie: '', addEventListener() {}, removeEventListener() {} }
const element = () => ({ nodeType: 1, nodeName: 'DIV', tagName: 'DIV', namespaceURI: 'http://www.w3.org/1999/xhtml', ownerDocument: document, addEventListener() {}, removeEventListener() {} })

let browser: ReturnType<typeof fakeBrowser>
let mounted: Array<() => Promise<void>> = []

beforeEach(() => {
  browser = fakeBrowser({ document, HTMLIFrameElement: class {}, IS_REACT_ACT_ENVIRONMENT: true })
})

// Unmount whatever a test left mounted while the stand-ins are still there.
afterEach(async () => {
  try {
    for (const unmount of mounted) {
      await unmount()
    }
  } finally {
    mounted = []
    browser.restore()
  }
})

/** Render a hook, keeping what it returned on the latest render. */
async function render<P, T>(use: (props: P) => T, props: P) {
  const result = { current: undefined as T }
  const root = createRoot(element() as any)
  let unmounted = false
  const unmount = async () => {
    if (!unmounted) {
      unmounted = true
      await act(async () => root.unmount())
    }
  }

  mounted.push(unmount)
  const Probe = ({ props }: { props: P }) => {
    result.current = use(props)

    return null
  }

  await act(async () => root.render(createElement(Probe, { props })))

  return {
    result,
    rerender: (next: P) => act(async () => root.render(createElement(Probe, { props: next }))),
    unmount,
  }
}

describe('react useChallenge', () => {
  test('picks the component for the current factor', async () => {
    const Code = () => null
    const Recovery = () => null
    const factors = { totp: Code, recovery: Recovery }
    const { result, rerender, unmount } = await render(props => useChallenge(props, factors), challengeProps({ factor: 'totp' }))

    expect(result.current.Component).toBe(Code)

    await rerender(challengeProps({ factor: 'recovery' }))
    expect(result.current.Component).toBe(Recovery)

    await rerender(challengeProps({ factor: 'sms' }))
    expect(result.current.Component).toBeUndefined()

    await unmount()
  })

  test('posts the fields and the authenticator to the factor, then clears the secrets', async () => {
    const { result } = await render(props => useChallenge(props, {}), challengeProps({ purpose: 'login', factor: 'totp', authenticator: { factor: 'totp', id: 'a1', name: 'Phone' } }))

    await act(async () => {
      result.current.form.setData({ code: '123456', password: '', trust: true })
    })
    await act(async () => result.current.submit({ remember: true }))

    expect(browser.visits).toHaveLength(1)
    const [visit] = browser.visits
    expect(visit.method).toBe('post')
    expect(visit.url).toBe('/login/challenge/totp')
    expect(visit.data).toEqual({ code: '123456', password: '', trust: true, remember: true, authenticator: 'a1' })
    expect(visit.options.preserveScroll).toBe(true)

    await act(async () => visit.options.onFinish())

    expect(result.current.form.data.code).toBe('')
    expect(result.current.form.data.trust).toBe(true)
  })

  test('prompts for the key and submits the credential', async () => {
    const { result } = await render(props => useChallenge(props, {}), challengeProps())
    await act(async () => {
      result.current.form.setError('credential', 'Left over from last time.')
    })

    await act(async () => {
      const verifying = result.current.verifyKey()
      expect(browser.prompts[0].options).toEqual({ challenge: 'confirm' })
      browser.prompts[0].resolve({ id: 'key' })
      await verifying
    })

    expect(result.current.form.errors).toEqual({})
    expect(browser.visits.map(({ method, url }) => `${method} ${url}`)).toEqual(['post /confirm/security-key'])
    expect(browser.visits[0].data).toMatchObject({ credential: { id: 'key' }, authenticator: 'k1' })
  })

  test('does nothing when the user closes the prompt', async () => {
    const { result } = await render(props => useChallenge(props, {}), challengeProps())

    await act(async () => {
      const verifying = result.current.verifyKey()
      browser.prompts[0].reject(cancelled())
      await verifying
    })

    expect(browser.visits).toEqual([])
    expect(result.current.form.errors).toEqual({})
  })

  test('shows a failed prompt on the credential field', async () => {
    const { result } = await render(props => useChallenge(props, {}), challengeProps())

    await act(async () => {
      const verifying = result.current.verifyKey()
      browser.prompts[0].reject(new DOMException('This key is not registered.', 'InvalidStateError'))
      await verifying
    })

    expect(browser.visits).toEqual([])
    expect(result.current.form.errors).toEqual({ credential: 'This key is not registered.' })
  })

  test('keeps one key prompt across renders, so a second click replaces the first', async () => {
    const { result, rerender } = await render(props => useChallenge(props, {}), challengeProps())

    let first!: Promise<void>
    let second!: Promise<void>

    await act(async () => {
      first = result.current.verifyKey()
    })
    await rerender(challengeProps())
    await act(async () => {
      second = result.current.verifyKey()
    })

    expect(browser.prompts[0].signal?.aborted).toBe(true)

    await act(async () => {
      await tick()
      browser.prompts[1].resolve({ id: 'key' })
      await Promise.all([first, second])
    })

    expect(browser.visits).toHaveLength(1)
    expect(browser.visits[0].data.credential).toEqual({ id: 'key' })
  })

  test('switches to another authenticator and sends codes', async () => {
    const props = challengeProps({ purpose: 'login', factor: 'email', authenticator: { factor: 'email', id: 'e1', name: 'Email' } })
    const { result } = await render(props => useChallenge(props, {}), props)

    result.current.switchTo(props.alternatives[0])
    result.current.switchTo(props.alternatives[1])
    result.current.send()

    expect(browser.visits.map(({ method, url, data }) => ({ method, url, data }))).toEqual([
      { method: 'get', url: '/login/challenge/recovery', data: { authenticator: 'r1' } },
      { method: 'get', url: '/login/challenge/password', data: {} },
      { method: 'post', url: '/login/challenge/email/send', data: { authenticator: 'e1' } },
    ])
    expect(browser.visits[2].options).toEqual({ preserveScroll: true })
  })
})

describe('react usePasskeyLogin', () => {
  test('offers autofill once mounted, and lets go of it when unmounted', async () => {
    const { result, unmount } = await render(options => usePasskeyLogin(options), { autofill: true })
    await act(tick)

    expect(result.current.supported).toBe(true)
    expect(browser.requested).toEqual(['/login/passkey/options'])
    expect(browser.prompts.map(prompt => prompt.autofill)).toEqual([true])

    await unmount()

    expect(browser.prompts[0].signal?.aborted).toBe(true)
  })

  test('is not supported without webauthn', async () => {
    delete (globalThis as any).PublicKeyCredential

    const { result, unmount } = await render(() => usePasskeyLogin(), undefined)

    expect(result.current.supported).toBe(false)
    await unmount()
  })

  test('starts over when autofill or the factor changes', async () => {
    const { rerender, unmount } = await render(options => usePasskeyLogin(options), { autofill: true })
    await act(tick)

    await rerender({ autofill: true, factor: 'security-key' })
    await act(tick)

    expect(browser.prompts[0].signal?.aborted).toBe(true)
    expect(browser.requested).toEqual(['/login/passkey/options', '/login/security-key/options'])

    await rerender({ autofill: false, factor: 'security-key' })
    await act(tick)

    expect(browser.prompts[1].signal?.aborted).toBe(true)
    expect(browser.prompts).toHaveLength(2)

    await unmount()
  })

  test('reads the latest remember without starting over', async () => {
    const { result, rerender, unmount } = await render(options => usePasskeyLogin(options), { autofill: true, remember: () => false })
    await act(tick)

    await rerender({ autofill: true, remember: () => true })
    await act(tick)

    expect(browser.prompts).toHaveLength(1)
    expect(browser.prompts[0].signal?.aborted).toBe(false)

    browser.prompts[0].resolve({ id: 'passkey' })
    await act(tick)

    expect(browser.visits[0]).toMatchObject({ url: '/login/passkey', data: { credential: { id: 'passkey' }, remember: true } })
    await unmount()
  })

  test('returns processing and the error as they change', async () => {
    const { result, unmount } = await render(() => usePasskeyLogin(), undefined)

    await act(async () => {
      result.current.signIn()
      await tick()
    })
    expect(result.current.processing).toBe(true)
    expect(result.current.error).toBeNull()

    await act(async () => {
      browser.prompts[0].reject(new Error('The passkey could not be read.'))
      await tick()
    })
    expect(result.current.processing).toBe(false)
    expect(result.current.error).toBe('The passkey could not be read.')

    // Trying again clears the error, and doesn't remember the device unless asked.
    await act(async () => {
      result.current.signIn()
      await tick()
    })
    expect(result.current.processing).toBe(true)
    expect(result.current.error).toBeNull()

    await act(async () => {
      browser.prompts[1].resolve({ id: 'passkey' })
      await tick()
    })
    expect(browser.visits[0]).toMatchObject({ url: '/login/passkey', data: { credential: { id: 'passkey' }, remember: false } })

    await unmount()
  })
})
