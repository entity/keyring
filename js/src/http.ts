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
   * fetch()'s credentials. By default "include" when baseUrl is on another
   * origin, so the session cookie goes with each request, and "same-origin"
   * otherwise.
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

let fetchingCsrfCookie: Promise<void> | null = null

/**
 * Say once, at startup, how json() sends requests. Only the options given
 * change, and passing one as undefined puts it back to its default.
 */
export function configureRequests(options: RequestOptions): void {
  if ('baseUrl' in options) {
    settings.baseUrl = base(options.baseUrl)
  }

  if ('credentials' in options) {
    settings.credentials = options.credentials
  }

  if ('csrfCookie' in options) {
    settings.csrfCookie = options.csrfCookie || null
  }

  if ('fetch' in options) {
    settings.fetch = options.fetch
  }
}

/**
 * Small JSON requests for the steps that aren't page visits (fetching
 * WebAuthn options, enrolling). Sends Laravel's XSRF cookie like Inertia does.
 */
export async function json<T = any>(method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, body?: unknown): Promise<T> {
  const target = resolve(url)
  let token = isTrusted(target) ? xsrf() : null

  if (token === null && method !== 'GET' && settings.csrfCookie !== null && isTrusted(target) && typeof document !== 'undefined') {
    await csrfCookie()
    token = xsrf()
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
  fetchingCsrfCookie ??= send(resolve(settings.csrfCookie!), { method: 'GET' })
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

function send(url: string, { headers, ...init }: Omit<RequestInit, 'headers'> & { headers?: Record<string, string> }): Promise<Response> {
  // Called on its own, not as settings.fetch(), since a browser's fetch
  // refuses to run with anything but the window as `this`.
  const request = settings.fetch ?? fetch

  return request(url, {
    ...init,
    credentials: settings.credentials ?? (settings.baseUrl !== '' && origin(settings.baseUrl) !== pageOrigin() ? 'include' : 'same-origin'),
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

function isAbsolute(url: string): boolean {
  return /^[a-z][a-z\d+.-]*:/i.test(url) || url.startsWith('//')
}

/**
 * A path goes to the baseUrl, when there is one. A full URL goes where it says.
 */
function resolve(url: string): string {
  if (settings.baseUrl === '' || isAbsolute(url)) {
    return url
  }

  return settings.baseUrl + (url.startsWith('/') ? url : `/${url}`)
}

/**
 * Whether a request may carry the XSRF token: it goes to the page's own
 * origin or to the baseUrl's, not to whatever full URL json() was handed.
 */
function isTrusted(url: string): boolean {
  if (!isAbsolute(url)) {
    return true
  }

  const target = origin(url)

  return target !== null && (target === pageOrigin() || (settings.baseUrl !== '' && target === origin(settings.baseUrl)))
}

function origin(url: string): string | null {
  try {
    return new URL(url, pageOrigin() ?? undefined).origin
  } catch {
    return null
  }
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
