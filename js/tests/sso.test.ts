import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { configureRequests, KeyringRequestError } from '../src/http'
import { configureRoutes, routes } from '../src/routes'
import { confirmWithProvider, linkProvider, signInWithProvider } from '../src/sso'
import { standIn } from './browser'

// Each request is recorded and answered by its URL, and every page the
// browser is sent to is too.
type Request = { url: string, method: string, body: any }

let requests: Request[] = []
let visited: string[] = []
let answer: (url: string) => Response
let restore = () => {}

beforeEach(() => {
  requests = []
  visited = []
  answer = () => new Response('{}', { status: 200 })

  restore = standIn({
    location: { origin: 'https://app.example.com', assign: (url: string) => visited.push(url) },
    document: { cookie: 'XSRF-TOKEN=abc' },
    fetch: (url: string, init: RequestInit) => {
      requests.push({ url, method: init.method!, body: init.body === undefined ? undefined : JSON.parse(init.body as string) })

      return Promise.resolve(answer(url))
    },
  })
})

afterEach(() => {
  configureRequests({ baseUrl: null })
  configureRoutes({ prefix: '' })
  restore()
})

describe('signing in with a provider', () => {
  test('asks for the provider\'s url, then sends the browser there', async () => {
    answer = () => Response.json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?state=abc' })

    await signInWithProvider('google')

    expect(requests).toEqual([{ url: '/auth/google/redirect', method: 'GET', body: undefined }])
    expect(visited).toEqual(['https://accounts.google.com/o/oauth2/v2/auth?state=abc'])
  })

  test('asks to be remembered when told to, of laravel wherever it is', async () => {
    configureRequests({ baseUrl: 'https://api.example.com' })
    configureRoutes({ prefix: 'auth' })
    answer = () => Response.json({ url: 'https://github.com/login/oauth/authorize?state=abc' })

    await signInWithProvider('github', { remember: true })

    expect(requests[0].url).toBe('https://api.example.com/auth/auth/github/redirect?remember=1')
    expect(visited).toEqual(['https://github.com/login/oauth/authorize?state=abc'])
  })

  test('goes nowhere when the provider can\'t be reached', async () => {
    answer = () => Response.json({ message: 'We couldn\'t sign you in.', errors: { email: ['We couldn\'t sign you in with Google.'] } }, { status: 422 })

    const error = await signInWithProvider('google').catch(caught => caught)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.errors).toEqual({ email: ['We couldn\'t sign you in with Google.'] })
    expect(visited).toEqual([])
  })
})

describe('linking a provider', () => {
  test('begins the enrollment, then sends the browser to the provider', async () => {
    answer = () => Response.json({ status: 'enrollment-started', factor: 'sso', enrollment: { provider: 'google', url: 'https://accounts.google.com/o/oauth2/v2/auth?state=abc' } })

    await linkProvider('google')

    expect(requests).toEqual([{ url: '/user/authenticators/sso', method: 'POST', body: { provider: 'google' } }])
    expect(visited).toEqual(['https://accounts.google.com/o/oauth2/v2/auth?state=abc'])
  })

  test('sends the password where it\'s given', async () => {
    answer = () => Response.json({ status: 'enrollment-started', factor: 'sso', enrollment: { provider: 'google', url: 'https://accounts.google.com/o/oauth2/v2/auth?state=abc' } })

    await linkProvider('google', { password: 'hunter2' })

    expect(requests).toEqual([{ url: '/user/authenticators/sso', method: 'POST', body: { provider: 'google', password: 'hunter2' } }])
  })

  test('goes nowhere until the user has confirmed it\'s them', async () => {
    answer = () => Response.json({ status: 'confirm', page: 'confirm', redirect: '/confirm' }, { status: 423 })

    const error = await linkProvider('google').catch(caught => caught)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(error.status).toBe(423)
    expect(visited).toEqual([])
  })
})

describe('confirming with a provider', () => {
  test('asks for the provider\'s url for the link, then sends the browser there', async () => {
    answer = () => Response.json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?max_age=0&state=abc' })

    await confirmWithProvider('01jcm5v3a9')

    expect(requests).toEqual([{ url: '/confirm/sso/redirect?authenticator=01jcm5v3a9', method: 'GET', body: undefined }])
    expect(visited).toEqual(['https://accounts.google.com/o/oauth2/v2/auth?max_age=0&state=abc'])
  })

  test('goes nowhere when the confirm is over', async () => {
    answer = () => Response.json({ message: 'That took too long.', errors: { email: ['That took too long.'] } }, { status: 422 })

    const error = await confirmWithProvider('01jcm5v3a9').catch(caught => caught)

    expect(error).toBeInstanceOf(KeyringRequestError)
    expect(visited).toEqual([])
  })
})

test('the routes keep a provider\'s name inside its own path segment', () => {
  expect(routes.ssoRedirect('google')).toBe('/auth/google/redirect')
  expect(routes.ssoCallback('microsoft')).toBe('/auth/microsoft/callback')
  expect(routes.ssoRedirect('../logout')).toBe('/auth/..%2Flogout/redirect')
  expect(() => routes.ssoCallback('..')).toThrow(TypeError)
  expect(routes.ssoConfirm()).toBe('/confirm/sso/redirect')
  expect(routes.ssoConfirm('a&b=c')).toBe('/confirm/sso/redirect?authenticator=a%26b%3Dc')
})
