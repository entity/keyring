/**
 * A fetch-compatible function: takes a URL and init, resolves to a Response.
 * The headers are always a plain object, so a wrapper can spread them.
 */
export type Fetcher = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>

export interface RequestOptions {
  /**
   * Where Laravel is, when the frontend is served from somewhere else, such
   * as "https://api.example.com". Every path json() is given, Keyring's
   * routes included, is sent there. null puts it back to the page's origin.
   */
  baseUrl?: string | null
  /**
   * fetch()'s credentials. By default "include" for a request to the
   * baseUrl when it's on another origin than the page, or when there's no
   * page (rendering on the server), so the session cookie goes with it.
   * "same-origin" otherwise.
   */
  credentials?: RequestCredentials
  /**
   * A URL that sets the XSRF-TOKEN cookie, such as Sanctum's
   * "/sanctum/csrf-cookie". When it's set and the cookie isn't there,
   * json() fetches it before sending anything but a GET.
   */
  csrfCookie?: string | null
  /** Used in place of the global fetch(), for SSR or extra headers. */
  fetch?: Fetcher
}

const settings: { baseUrl: string, credentials?: RequestCredentials, csrfCookie: string | null, fetch?: Fetcher } = {
  baseUrl: '',
  csrfCookie: null,
}

const options = ['baseUrl', 'credentials', 'csrfCookie', 'fetch']

let fetchingCsrfCookie: Promise<void> | null = null

/**
 * Say once, at startup, how json() sends requests. Only the options given
 * change, and passing one as undefined puts it back to its default.
 */
export function configureRequests(given: RequestOptions): void {
  // A misspelt option, such as axios's "baseURL", would otherwise do nothing.
  for (const key of Object.keys(given)) {
    if (!options.includes(key)) {
      throw new TypeError(`Keyring has no request option [${key}]. The options are ${options.join(', ')}.`)
    }
  }

  if ('baseUrl' in given) {
    settings.baseUrl = base(given.baseUrl)
  }

  if ('credentials' in given) {
    settings.credentials = given.credentials
  }

  if ('csrfCookie' in given) {
    settings.csrfCookie = given.csrfCookie || null
  }

  if ('fetch' in given) {
    settings.fetch = given.fetch
  }
}

/**
 * Small JSON requests for the steps that aren't page visits (fetching
 * WebAuthn options, enrolling). Sends Laravel's XSRF cookie like Inertia does.
 */
export async function json<T = any>(method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, body?: unknown): Promise<T> {
  const target = locate(url)
  let token = target.trusted ? xsrf() : null

  if (token === null && method !== 'GET' && settings.csrfCookie !== null && target.trusted && typeof document !== 'undefined') {
    await csrfCookie()
    token = xsrf()

    // Laravel set it, but for a domain this page isn't on, so posting now
    // would only get a 419.
    if (token === null) {
      throw new KeyringRequestError(
        419,
        'The XSRF-TOKEN cookie was set, but this page can\'t read it. Set SESSION_DOMAIN to a domain the frontend and Laravel share.',
        {},
        {},
      )
    }
  }

  const response = await send(target, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token && { 'X-XSRF-TOKEN': token }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  // An error page may not be JSON; the status still tells the story.
  const data = response.status === 204 ? {} : await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new KeyringRequestError(response.status, data?.message ?? 'Request failed', data?.errors ?? {}, data)
  }

  return data as T
}

export class KeyringRequestError extends Error {
  constructor(
    public status: number,
    message: string,
    public errors: Record<string, string[]>,
    public data: any,
  ) {
    super(message)
  }
}

/**
 * Fetch the CSRF cookie, once for however many requests are waiting on it.
 */
function csrfCookie(): Promise<void> {
  fetchingCsrfCookie ??= send(locate(settings.csrfCookie!), { method: 'GET' })
    .then((response) => {
      if (!response.ok) {
        throw new KeyringRequestError(response.status, 'Could not fetch the CSRF cookie', {}, {})
      }
    })
    .finally(() => {
      fetchingCsrfCookie = null
    })

  return fetchingCsrfCookie
}

function send(target: Target, { headers, ...init }: Omit<RequestInit, 'headers'> & { headers?: Record<string, string> }): Promise<Response> {
  // Called on its own, not as settings.fetch(), since a browser's fetch
  // refuses to run with anything but the window as `this`.
  const request = settings.fetch ?? fetch

  return request(target.url, {
    ...init,
    credentials: settings.credentials ?? (target.toBase && origin(settings.baseUrl) !== pageOrigin() ? 'include' : 'same-origin'),
    headers: {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...headers,
    },
  })
}

/**
 * The baseUrl as an origin and an optional path, without a trailing slash.
 */
function base(value: string | null | undefined): string {
  if (!value) {
    return ''
  }

  let url: URL

  try {
    url = new URL(value)
  } catch {
    throw new TypeError(`Keyring's baseUrl must be an absolute URL, such as https://api.example.com, not [${value}].`)
  }

  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash) {
    throw new TypeError(`Keyring's baseUrl must be an http or https URL without credentials, a query or a fragment, not [${value}].`)
  }

  return url.origin + url.pathname.replace(/\/+$/, '')
}

/**
 * Where a request goes: the URL to fetch, whether it's to the baseUrl, and
 * whether it may carry the XSRF token.
 */
type Target = { url: string, toBase: boolean, trusted: boolean }

/**
 * Decided the way the browser will read the URL, not by how it looks:
 * "/\evil.test", " //evil.test" and "\thttps://evil.test" are all full URLs
 * to a browser. A path is one that lands on whatever origin it's resolved
 * against. It goes to the baseUrl when there is one, and to the page
 * otherwise. Only the page's own origin and the baseUrl's get the token.
 */
function locate(url: string): Target {
  const one = parse(url, 'https://one.keyring.invalid')
  const two = parse(url, 'https://two.keyring.invalid')
  const isPath = one !== null && two !== null && one.origin !== two.origin

  if (isPath && settings.baseUrl !== '') {
    return { url: settings.baseUrl + one.pathname + one.search + one.hash, toBase: true, trusted: true }
  }

  if (isPath) {
    // With no page, as when rendering on the server, a path has nowhere else
    // to go. With one, it goes where the document's base URL says.
    const page = typeof document !== 'undefined' && typeof document.baseURI === 'string' ? document.baseURI : pageOrigin()

    return { url, toBase: false, trusted: page === null || parse(url, page)?.origin === pageOrigin() }
  }

  const target = one?.origin ?? null
  const toBase = target !== null && settings.baseUrl !== '' && target === origin(settings.baseUrl)

  return { url, toBase, trusted: target !== null && target !== 'null' && (target === pageOrigin() || toBase) }
}

function parse(url: string, base: string): URL | null {
  try {
    return new URL(url, base)
  } catch {
    return null
  }
}

function origin(url: string): string | null {
  return parse(url, 'https://keyring.invalid')?.origin ?? null
}

function pageOrigin(): string | null {
  return typeof location !== 'undefined' && typeof location.origin === 'string' ? location.origin : null
}

function xsrf(): string | null {
  if (typeof document === 'undefined') {
    return null
  }

  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)

  return match ? decodeURIComponent(match[1]) : null
}
