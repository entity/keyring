import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { enroll, removeAuthenticator } from '../src/enroll'
import { KeyringRequestError } from '../src/http'
import { createCredential, fromBase64Url, getCredential, toBase64Url } from '../src/webauthn'

// A browser without the JSON helpers (parse*FromJSON, toJSON), so the
// conversions Keyring does itself run. Each call to navigator.credentials
// is recorded and answered with a fake credential.
class FakeCredential {
  id = 'key-1'
  rawId = Uint8Array.from([1, 2, 3]).buffer
  type = 'public-key'
  authenticatorAttachment = 'platform'

  constructor(public response: Record<string, any>) {}

  getClientExtensionResults() {
    return {}
  }
}

const bytes = (...values: number[]) => Uint8Array.from(values).buffer

let calls: Array<{ method: string, options: any }> = []
let requests: Array<{ method: string, url: string, body: any }> = []
let answers: Array<{ status: number, body: any }> = []

beforeEach(() => {
  calls = []
  requests = []
  answers = []

  Object.assign(globalThis, {
    window: globalThis,
    PublicKeyCredential: FakeCredential,
    document: { cookie: 'XSRF-TOKEN=abc%3D' },
    navigator: {
      credentials: {
        create: async (options: any) => {
          calls.push({ method: 'create', options })

          return new FakeCredential({
            clientDataJSON: bytes(9),
            attestationObject: bytes(8),
            getTransports: () => ['internal'],
          })
        },
        get: async (options: any) => {
          calls.push({ method: 'get', options })

          return new FakeCredential({ clientDataJSON: bytes(9), authenticatorData: bytes(7), signature: bytes(6), userHandle: null })
        },
      },
    },
    fetch: async (url: string, init: any) => {
      requests.push({ method: init.method, url, body: init.body === undefined ? undefined : JSON.parse(init.body), headers: init.headers } as any)
      const { status, body } = answers.shift() ?? { status: 200, body: {} }

      return new Response(JSON.stringify(body), { status })
    },
  })
})

afterEach(() => {
  for (const name of ['window', 'PublicKeyCredential', 'navigator', 'document', 'fetch']) {
    delete (globalThis as any)[name]
  }
})

describe('creating a credential', () => {
  test('turns the base64url fields into bytes, and the result back into json', async () => {
    const credential = await createCredential({
      challenge: toBase64Url(bytes(1, 2)),
      user: { id: toBase64Url(bytes(3)), name: 'taylor@example.com' },
      excludeCredentials: [{ type: 'public-key', id: toBase64Url(bytes(4)) }],
    })

    const { publicKey } = calls[0].options
    expect(new Uint8Array(publicKey.challenge)).toEqual(Uint8Array.from([1, 2]))
    expect(new Uint8Array(publicKey.user.id)).toEqual(Uint8Array.from([3]))
    expect(publicKey.user.name).toBe('taylor@example.com')
    expect(new Uint8Array(publicKey.excludeCredentials[0].id)).toEqual(Uint8Array.from([4]))

    expect(credential).toEqual({
      id: 'key-1',
      rawId: 'AQID',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: { clientDataJSON: 'CQ', attestationObject: 'CA', transports: ['internal'] },
    })
  })

  test('says so when the browser has no webauthn', async () => {
    delete (globalThis as any).PublicKeyCredential

    await expect(createCredential({})).rejects.toThrow('does not support passkeys')
  })
})

describe('getting a credential', () => {
  test('sends allowed keys as bytes, and asks for autofill when told to', async () => {
    const credential = await getCredential(
      { challenge: toBase64Url(bytes(5)), allowCredentials: [{ type: 'public-key', id: toBase64Url(bytes(6)) }] },
      { autofill: true },
    )

    expect(calls[0].options.mediation).toBe('conditional')
    expect(new Uint8Array(calls[0].options.publicKey.allowCredentials[0].id)).toEqual(Uint8Array.from([6]))
    expect(credential.response).toEqual({ clientDataJSON: 'CQ', authenticatorData: 'Bw', signature: 'Bg', userHandle: null })
  })

  test('asks in a modal by default', async () => {
    await getCredential({ challenge: toBase64Url(bytes(5)) })

    expect(calls[0].options.mediation).toBeUndefined()
    expect(calls[0].options.publicKey.allowCredentials).toEqual([])
  })
})

describe('enrolling', () => {
  test('runs the ceremony between beginning and confirming a passkey', async () => {
    answers.push(
      { status: 200, body: { factor: 'passkey', enrollment: { options: { challenge: toBase64Url(bytes(1)), rp: { id: 'example.com' }, user: { id: 'AQ' } } } } },
      { status: 200, body: { authenticator: { id: 'a1', name: 'MacBook' } } },
    )

    const result = await enroll('passkey', { name: 'MacBook' })

    expect(requests.map(request => `${request.method} ${request.url}`)).toEqual([
      'POST /user/authenticators/passkey',
      'POST /user/authenticators/passkey/confirm',
    ])
    expect(requests[1].body.name).toBe('MacBook')
    expect(requests[1].body.credential.id).toBe('key-1')
    expect((requests[0] as any).headers['X-XSRF-TOKEN']).toBe('abc=')
    expect(result.authenticator.id).toBe('a1')
  })

  test('confirms factors without a ceremony as they are', async () => {
    answers.push({ status: 200, body: { factor: 'recovery', enrollment: { codes: ['a', 'b'] } } }, { status: 200, body: { authenticator: { id: 'r1' } } })

    await enroll('recovery')

    expect(calls).toEqual([])
    expect(requests[1].body).toEqual({})
  })

  test('hands back the validation errors when removing fails', async () => {
    answers.push({ status: 422, body: { message: 'Enter your password', errors: { password: ['Enter your password'] } } })

    const error = await removeAuthenticator('a1').catch(error => error)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(422)
    expect(error.errors.password).toEqual(['Enter your password'])
    expect(requests[0]).toMatchObject({ method: 'DELETE', url: '/user/authenticators/a1', body: undefined })
  })
})

test('base64url decoding accepts what the server sends', () => {
  expect(new Uint8Array(fromBase64Url('-_8'))).toEqual(Uint8Array.from([251, 255]))
})
