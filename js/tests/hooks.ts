import { router } from '@inertiajs/core'
import { spyOn } from 'bun:test'
import { standIn } from './browser'

// What the Vue and React hook tests share: the browser's key prompt, the
// options request and Inertia's router, as stand-ins the tests drive by
// hand. Keyring's own modules and Inertia's useForm stay real. Call
// restore() in afterEach: Bun runs every file in the one process.
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

  const credentials = {
    get: ({ publicKey, mediation, signal }: { publicKey: object, mediation?: string, signal?: AbortSignal }) => new Promise((resolve, reject) => {
      prompts.push({
        options: publicKey,
        autofill: mediation === 'conditional',
        signal,
        // A browser that hands back no credential at all resolves to null.
        resolve: credential => resolve(credential && new FakeCredential(credential)),
        reject,
      })
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
    }),
  }

  const restoreGlobals = standIn({
    window: globalThis,
    PublicKeyCredential: FakeCredential,
    document: { cookie: '' },
    navigator: { credentials },
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

  return {
    prompts,
    requested,
    visits,
    restore() {
      post.mockRestore()
      get.mockRestore()
      restoreGlobals()
    },
  }
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
