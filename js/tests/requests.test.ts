import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { enroll } from '../src/enroll'
import { configureRequests, json, KeyringRequestError } from '../src/http'
import { passkeyCredential } from '../src/login'
import { configureRoutes } from '../src/routes'
import { listSessions } from '../src/sessions'
import { standIn } from './browser'

// A frontend on app.example.com, unless a test says otherwise. Each request
// is recorded, and a test may answer one by its URL.
type Request = { url: string, method: string, credentials: RequestCredentials, headers: Record<string, string>, body: any }

let requests: Request[] = []
let answer: (url: string) => Response | Promise<Response>
let restore = () => {}

function record(url: string, init: RequestInit): Promise<Response> {
  requests.push({
    url,
    method: init.method!,
    credentials: init.credentials!,
    headers: init.headers as Record<string, string>,
    body: init.body === undefined ? undefined : JSON.parse(init.body as string),
  })

  return Promise.resolve(answer(url))
}

beforeEach(() => {
  requests = []
  answer = () => new Response('{}', { status: 200 })

  restore = standIn({
    location: { origin: 'https://app.example.com' },
    document: { cookie: 'XSRF-TOKEN=abc%3D' },
    fetch: record,
  })
})

// The settings are one object for the whole process, like the routes.
afterEach(() => {
  configureRequests({ baseUrl: null, credentials: undefined, csrfCookie: null, fetch: undefined })
  configureRoutes({ prefix: '' })
  restore()
})

describe('by default', () => {
  test('sends paths to the page\'s own origin, with its cookies and the xsrf token', async () => {
    await json('POST', '/user/password', { password: 'secret' })

    expect(requests[0]).toMatchObject({
      url: '/user/password',
      method: 'POST',
      credentials: 'same-origin',
      body: { password: 'secret' },
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-XSRF-TOKEN': 'abc=' },
    })
  })

  test('keeps the xsrf token from a full url on another origin', async () => {
    await json('POST', 'https://elsewhere.example/hook')
    await json('POST', 'https://app.example.com/user/password')

    expect(requests[0].headers['X-XSRF-TOKEN']).toBeUndefined()
    expect(requests[1].headers['X-XSRF-TOKEN']).toBe('abc=')
  })

  test('sends no token when the url can\'t be read, or the page has no cookies to read', async () => {
    await json('POST', 'https://exa mple.com/x')

    delete (globalThis as any).document
    await json('POST', '/user/password')

    expect(requests.map(request => request.headers['X-XSRF-TOKEN'])).toEqual([undefined, undefined])
  })

  test('sends no token where the document\'s base url points a path at another origin', async () => {
    ;(document as any).baseURI = 'https://cdn.example/assets/'
    await json('POST', '/user/password')

    ;(document as any).baseURI = 'https://app.example.com/settings/'
    await json('POST', 'user/password')

    expect(requests.map(request => request.headers['X-XSRF-TOKEN'])).toEqual([undefined, 'abc='])
  })
})

// What a browser reads as a full URL to another origin, however much it
// looks like a path: backslashes count as slashes, and tabs, newlines and
// leading spaces are dropped.
describe('a url that only looks like a path', () => {
  const lookalikes = ['/\\evil.test/x', '\\\\evil.test/x', ' //evil.test/x', '/\t/evil.test/x', '\n//evil.test/x', '\thttps://evil.test/x', 'javascript:alert(1)']

  for (const baseUrl of [null, 'https://api.example.com']) {
    test(`gets no token, no csrf cookie and no cookies ${baseUrl ? 'with' : 'without'} a base url`, async () => {
      configureRequests({ baseUrl, csrfCookie: '/sanctum/csrf-cookie' })

      for (const url of lookalikes) {
        await json('POST', url)
      }

      document.cookie = ''

      for (const url of lookalikes) {
        await json('POST', url)
      }

      expect(requests.map(request => request.url)).toEqual([...lookalikes, ...lookalikes])
      expect(requests.map(request => request.headers['X-XSRF-TOKEN'])).toEqual(lookalikes.flatMap(() => [undefined, undefined]))
      expect(requests.map(request => request.credentials)).toEqual(lookalikes.flatMap(() => ['same-origin', 'same-origin']))
    })
  }
})

describe('with a base url', () => {
  test('sends every path there, after the route prefix, with the session cookie', async () => {
    configureRequests({ baseUrl: 'https://api.example.com/' })
    configureRoutes({ prefix: 'auth' })

    await listSessions()
    await json('GET', 'user/devices')

    expect(requests.map(({ url, credentials }) => ({ url, credentials }))).toEqual([
      { url: 'https://api.example.com/auth/user/sessions', credentials: 'include' },
      { url: 'https://api.example.com/user/devices', credentials: 'include' },
    ])
  })

  test('keeps the path it has', async () => {
    configureRequests({ baseUrl: 'https://example.com/backend//' })

    await passkeyCredential('passkey').catch(() => {})

    expect(requests[0].url).toBe('https://example.com/backend/login/passkey/options')
  })

  // OWASP ASVS 5.0.0, 1.2.2: a value put into a URL stays in its segment.
  test('keeps an encoded id in its own segment on the base url', async () => {
    configureRequests({ baseUrl: 'https://api.example.com' })

    await json('DELETE', '/user/sessions/9f2c%2F..%2F..%2Flogout')

    expect(new URL(requests[0].url).pathname).toBe('/user/sessions/9f2c%2F..%2F..%2Flogout')
  })

  test('sends the xsrf token to the base url, and not to another origin', async () => {
    configureRequests({ baseUrl: 'https://api.example.com' })

    await json('POST', '/login')
    await json('POST', 'https://api.example.com/logout')
    await json('POST', 'https://elsewhere.example/hook')
    await json('POST', '//elsewhere.example/hook')

    expect(requests.map(request => request.headers['X-XSRF-TOKEN'])).toEqual(['abc=', 'abc=', undefined, undefined])
  })

  test('sends cookies only to the base url, not to a full url elsewhere', async () => {
    configureRequests({ baseUrl: 'https://api.example.com' })

    await json('GET', 'https://elsewhere.example/feed')
    await json('GET', 'https://api.example.com/user/sessions')
    await json('GET', 'https://app.example.com/me')

    expect(requests.map(request => request.credentials)).toEqual(['same-origin', 'include', 'same-origin'])
  })

  test('stays same-origin when the base url is the page\'s own origin', async () => {
    configureRequests({ baseUrl: 'https://app.example.com' })

    await json('GET', '/user/sessions')

    expect(requests[0]).toMatchObject({ url: 'https://app.example.com/user/sessions', credentials: 'same-origin' })
  })

  test('sends cookies when rendering on the server, where there is no page', async () => {
    delete (globalThis as any).location
    configureRequests({ baseUrl: 'http://laravel.internal:8000' })

    await json('GET', '/user/sessions')

    expect(requests[0]).toMatchObject({ url: 'http://laravel.internal:8000/user/sessions', credentials: 'include' })
  })

  test('uses the credentials it\'s told to', async () => {
    configureRequests({ baseUrl: 'https://api.example.com', credentials: 'omit' })

    await json('GET', '/user/sessions')

    expect(requests[0].credentials).toBe('omit')
  })

  test('goes back to the page\'s origin once cleared', async () => {
    configureRequests({ baseUrl: 'https://api.example.com' })
    configureRequests({ baseUrl: null })

    await json('GET', '/user/sessions')

    expect(requests[0]).toMatchObject({ url: '/user/sessions', credentials: 'same-origin' })
  })

  test('refuses one that isn\'t an absolute http url', () => {
    for (const baseUrl of ['api.example.com', '/api', 'ftp://api.example.com', 'javascript:alert(1)', 'https://user:pass@api.example.com', 'https://api.example.com/?x=1', 'https://api.example.com/#x']) {
      expect(() => configureRequests({ baseUrl })).toThrow(TypeError)
    }
  })

  test('refuses an option it doesn\'t have, such as axios\'s spelling', () => {
    expect(() => configureRequests({ baseURL: 'https://api.example.com' } as any)).toThrow('no request option [baseURL]')
  })
})

describe('the csrf cookie', () => {
  beforeEach(() => {
    document.cookie = ''
    configureRequests({ baseUrl: 'https://api.example.com', csrfCookie: '/sanctum/csrf-cookie' })
    answer = (url) => {
      if (url.endsWith('/sanctum/csrf-cookie')) {
        document.cookie = 'XSRF-TOKEN=fresh'

        return new Response(null, { status: 204 })
      }

      return new Response('{}', { status: 200 })
    }
  })

  test('is fetched before the first post, and the token sent with it', async () => {
    await json('POST', '/login', { email: 'taylor@example.com' })
    await json('POST', '/logout')

    expect(requests.map(({ method, url, credentials }) => `${method} ${url} ${credentials}`)).toEqual([
      'GET https://api.example.com/sanctum/csrf-cookie include',
      'POST https://api.example.com/login include',
      'POST https://api.example.com/logout include',
    ])
    expect(requests[0].headers).toEqual({ 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' })
    expect(requests[1].headers['X-XSRF-TOKEN']).toBe('fresh')
  })

  test('is fetched once for requests made together', async () => {
    await Promise.all([json('POST', '/login'), json('PATCH', '/user/authenticators/a1'), json('DELETE', '/user/sessions')])

    expect(requests.filter(request => request.url.endsWith('/sanctum/csrf-cookie'))).toHaveLength(1)
    expect(requests.slice(1).map(request => request.headers['X-XSRF-TOKEN'])).toEqual(['fresh', 'fresh', 'fresh'])
  })

  test('is fetched again once the cookie has gone', async () => {
    await json('POST', '/login')
    document.cookie = ''
    await json('POST', '/login')

    expect(requests.filter(request => request.url.endsWith('/sanctum/csrf-cookie'))).toHaveLength(2)
  })

  test('isn\'t needed for a get, or once the cookie is there', async () => {
    await json('GET', '/user/sessions')
    document.cookie = 'XSRF-TOKEN=abc'
    await json('POST', '/login')

    expect(requests.map(request => request.url)).toEqual(['https://api.example.com/user/sessions', 'https://api.example.com/login'])
  })

  test('says so when it was set for a domain this page can\'t read, rather than posting for a 419', async () => {
    answer = () => new Response(null, { status: 204 })

    const error = await json('POST', '/login').catch(error => error)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(419)
    expect(error.message).toContain('SESSION_DOMAIN')
    expect(requests.map(request => request.url)).toEqual(['https://api.example.com/sanctum/csrf-cookie'])
  })

  test('isn\'t fetched for a request to another origin', async () => {
    await json('POST', 'https://elsewhere.example/hook')

    expect(requests.map(request => request.url)).toEqual(['https://elsewhere.example/hook'])
  })

  test('isn\'t fetched on the server, where there are no cookies to read', async () => {
    delete (globalThis as any).document

    await json('POST', '/login')

    expect(requests.map(request => request.url)).toEqual(['https://api.example.com/login'])
  })

  test('throws with the status when it can\'t be fetched, and tries again next time', async () => {
    answer = () => new Response('', { status: 500 })

    const error = await enroll('passkey').catch(error => error)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(500)
    expect(requests).toHaveLength(1)

    await json('POST', '/login').catch(() => {})

    expect(requests.map(request => request.url)).toEqual([
      'https://api.example.com/sanctum/csrf-cookie',
      'https://api.example.com/sanctum/csrf-cookie',
    ])
  })
})

describe('a fetch of its own', () => {
  test('is used for every request, on its own rather than as a method', async () => {
    const seen: Array<{ self: unknown, url: string }> = []

    configureRequests({
      baseUrl: 'https://api.example.com',
      csrfCookie: '/sanctum/csrf-cookie',
      fetch: function (this: unknown, url, init) {
        seen.push({ self: this, url })
        document.cookie = 'XSRF-TOKEN=fresh'

        return record(url, init)
      },
    })
    document.cookie = ''

    await json('POST', '/login')

    expect(seen).toEqual([
      { self: undefined, url: 'https://api.example.com/sanctum/csrf-cookie' },
      { self: undefined, url: 'https://api.example.com/login' },
    ])
  })

  test('is dropped again when set to undefined', async () => {
    const own: string[] = []

    configureRequests({ fetch: async (url) => {
      own.push(url)

      return new Response('{}')
    } })
    await json('GET', '/a')
    configureRequests({ fetch: undefined })
    await json('GET', '/b')

    expect(own).toEqual(['/a'])
    expect(requests.map(request => request.url)).toEqual(['/b'])
  })
})
