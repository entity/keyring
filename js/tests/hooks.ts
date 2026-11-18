import { router } from '@inertiajs/core'
import { spyOn } from 'bun:test'
import { standIn } from './browser'

// What the Inertia, Vue and React tests share: the browser's key prompt, the
// options request and Inertia's router, as stand-ins the tests drive by
// hand. Keyring's own modules and Inertia's useForm stay real, and nothing
// is replaced with mock.module: Bun keeps a module mock for every file that
// runs after. Call restore() in afterEach: Bun runs every file in the one
// process.
export type Prompt = { options: object, autofill: boolean, signal?: AbortSignal, resolve: (credential: object | null) => void, reject: (error: unknown) => void }

export type Visit = { method: 'get' | 'post', url: string, data: Record<string, any>, options: Record<string, any> }

// A browser with the JSON helpers, so options reach the prompt as they were
// sent and a credential comes back as the JSON the test answered with.
class FakeCredential {
  static isConditionalMediationAvailable = async () => true
  static parseRequestOptionsFromJSON = (options: object) => options

  constructor(private json: object) {}

  toJSON() {
    return this.json
  }
}

export function fakeBrowser(globals: Record<string, unknown> = {}) {
  const prompts: Prompt[] = []
  const requested: string[] = []
  const visits: Visit[] = []
  const timers = new Set<ReturnType<typeof setTimeout>>()
  let open = 0

  const browser = {
    prompts,
    requested,
    visits,
    // A browser has one WebAuthn request open at a time, and takes a moment
    // to let go of one that was aborted. With this set to that moment in ms,
    // the stand-in does too, and refuses a request made before then the way
    // Chrome does, counting it in refused.
    letsGoAfter: null as number | null,
    refused: 0,
    restore() {
      timers.forEach(clearTimeout)
      post.mockRestore()
      get.mockRestore()
      restoreGlobals()
    },
  }

  const credentials = {
    get: ({ publicKey, mediation, signal }: { publicKey: object, mediation?: string, signal?: AbortSignal }) => new Promise((resolve, reject) => {
      if (browser.letsGoAfter !== null && open > 0) {
        browser.refused++

        return reject(new DOMException('A request is already pending.', 'OperationError'))
      }

      // A prompt settles once, however it ends: answered by hand, aborted,
      // or both, as when a passkey is picked just as the request is aborted.
      let settled = false
      open++
      const close = <T>(settle: (value: T) => void) => (value: T) => {
        if (settled) {
          return
        }

        settled = true
        open--
        settle(value)
      }
      const aborted = close(() => reject(new DOMException('Aborted', 'AbortError')))

      prompts.push({
        options: publicKey,
        autofill: mediation === 'conditional',
        signal,
        // A browser that hands back no credential at all resolves to null.
        resolve: close((credential: object | null) => resolve(credential && new FakeCredential(credential))),
        reject: close(reject),
      })
      signal?.addEventListener('abort', () => {
        if (browser.letsGoAfter === null) {
          return aborted(undefined)
        }

        const timer = setTimeout(() => {
          timers.delete(timer)
          aborted(undefined)
        }, browser.letsGoAfter)
        timers.add(timer)
      })
    }),
  }

  const restoreGlobals = standIn({
    window: globalThis,
    PublicKeyCredential: FakeCredential,
    document: { cookie: '' },
    navigator: { credentials },
    // Answers without a turn of the event loop, as the tests wait one tick.
    fetch: async (url: string) => {
      requested.push(url)

      return { ok: true, status: 200, json: async () => ({ options: { challenge: 'login' } }) }
    },
    ...globals,
  })

  const post = spyOn(router, 'post').mockImplementation(((url: string, data: any, options: any) => {
    visits.push({ method: 'post', url, data, options })
  }) as any)
  const get = spyOn(router, 'get').mockImplementation(((url: string, data: any, options: any) => {
    visits.push({ method: 'get', url, data, options })
  }) as any)

  return browser
}

export const tick = () => new Promise(resolve => setTimeout(resolve, 0))
export const cancelled = () => new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')

/** A challenge page's props, for a security key on the confirm page unless told otherwise. */
export function challengeProps(overrides: Record<string, any> = {}): any {
  return {
    purpose: 'confirm',
    factor: 'security-key',
    authenticator: { factor: 'security-key', id: 'k1', name: 'YubiKey' },
    challenge: { options: { challenge: 'confirm' } },
    alternatives: [
      { factor: 'recovery', id: 'r1', name: 'Recovery codes' },
      { factor: 'password', id: null, name: 'Password' },
    ],
    canTrustDevice: false,
    expiresAt: '2026-11-08T12:00:00Z',
    ...overrides,
  }
}
