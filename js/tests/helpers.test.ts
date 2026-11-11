import { describe, expect, test } from 'bun:test'
import { isWebAuthn } from '../src/enroll'
import { configureRoutes, routes } from '../src/routes'
import { fromBase64Url, toBase64Url } from '../src/webauthn'

describe('base64url', () => {
  test('round trips bytes, including ones that need padding', () => {
    for (const length of [0, 1, 2, 3, 32, 65]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37) % 256)

      expect(new Uint8Array(fromBase64Url(toBase64Url(bytes.buffer)))).toEqual(bytes)
    }
  })

  test('uses the url-safe alphabet without padding', () => {
    expect(toBase64Url(Uint8Array.from([251, 255]).buffer)).toBe('-_8')
  })
})

describe('enrollment', () => {
  test('runs the browser ceremony for any factor that sends creation options', () => {
    expect(isWebAuthn({ options: { challenge: 'abc', rp: { id: 'example.com' } } })).toBe(true)
    expect(isWebAuthn({ secret: 'ABC', qr: '<svg/>' })).toBe(false)
  })
})

describe('routes', () => {
  test('follow the server\'s route prefix, however its slashes are written', () => {
    configureRoutes({ prefix: 'account/' })

    expect(routes.login).toBe('/account/login')
    expect(routes.loginOptions('passkey')).toBe('/account/login/passkey/options')
    expect(routes.verify('confirm', 'totp')).toBe('/account/confirm/totp')
    expect(routes.enroll('totp')).toBe('/account/user/authenticators/totp')
    expect(routes.sessions()).toBe('/account/user/sessions')
    expect(routes.session('9f2c')).toBe('/account/user/sessions/9f2c')

    configureRoutes({ prefix: '' })

    expect(routes.login).toBe('/login')
    expect(routes.authenticator('abc')).toBe('/user/authenticators/abc')
  })

  test('use an overridden route as written', () => {
    configureRoutes({ prefix: 'account', login: '/sign-in' })

    expect(routes.login).toBe('/sign-in')

    configureRoutes({ prefix: '', login: '/login' })
  })

  test('follow a changed challenge prefix', () => {
    configureRoutes({ challengeBase: purpose => purpose === 'login' ? '/auth/challenge' : '/auth/confirm' })

    expect(routes.verify('login', 'totp')).toBe('/auth/challenge/totp')
    expect(routes.send('confirm', 'email-code')).toBe('/auth/confirm/email-code/send')
  })
})
