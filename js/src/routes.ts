/**
 * Keyring's default URLs. Override any of them with configureRoutes() if you
 * changed the prefix or routes on the server.
 */
export const routes = {
  login: '/login',
  loginOptions: (factor: string) => `/login/${factor}/options`,
  loginWith: (factor: string) => `/login/${factor}`,
  challenge: (purpose: Purpose, factor?: string) => `${purpose === 'login' ? '/login/challenge' : '/confirm'}${factor ? `/${factor}` : ''}`,
  verify: (purpose: Purpose, factor: string) => `${purpose === 'login' ? '/login/challenge' : '/confirm'}/${factor}`,
  send: (purpose: Purpose, factor: string) => `${purpose === 'login' ? '/login/challenge' : '/confirm'}/${factor}/send`,
  enroll: (factor: string) => `/user/authenticators/${factor}`,
  confirmEnrollment: (factor: string) => `/user/authenticators/${factor}/confirm`,
  authenticator: (id: string) => `/user/authenticators/${id}`,
}

export type Purpose = 'login' | 'confirm'

export function configureRoutes(overrides: Partial<typeof routes>): void {
  Object.assign(routes, overrides)
}
