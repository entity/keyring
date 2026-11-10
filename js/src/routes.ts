let prefix = ''
let login: string | null = null

/**
 * Keyring's default URLs. If you changed the `prefix` option on the server,
 * say so once with configureRoutes({ prefix }). Override single routes the
 * same way if you registered them yourself.
 */
export const routes = {
  get login(): string {
    return login ?? `${prefix}/login`
  },
  set login(path: string) {
    login = path
  },
  loginOptions: (factor: string) => `${prefix}/login/${factor}/options`,
  loginWith: (factor: string) => `${prefix}/login/${factor}`,
  challenge: (purpose: Purpose, factor?: string) => `${routes.challengeBase(purpose)}${factor ? `/${factor}` : ''}`,
  verify: (purpose: Purpose, factor: string) => `${routes.challengeBase(purpose)}/${factor}`,
  send: (purpose: Purpose, factor: string) => `${routes.challengeBase(purpose)}/${factor}/send`,
  challengeBase: (purpose: Purpose) => `${prefix}${purpose === 'login' ? '/login/challenge' : '/confirm'}`,
  enroll: (factor: string) => `${prefix}/user/authenticators/${factor}`,
  confirmEnrollment: (factor: string) => `${prefix}/user/authenticators/${factor}/confirm`,
  authenticator: (id: string) => `${prefix}/user/authenticators/${id}`,
}

export type Purpose = 'login' | 'confirm'

/**
 * `prefix` is the server's route prefix, with or without its slashes
 * ("account" and "/account/" both work). Anything else replaces one route.
 */
export function configureRoutes({ prefix: path, ...overrides }: Partial<typeof routes> & { prefix?: string }): void {
  if (path !== undefined) {
    const trimmed = path.replace(/^\/+|\/+$/g, '')

    prefix = trimmed === '' ? '' : `/${trimmed}`
  }

  Object.assign(routes, overrides)
}
