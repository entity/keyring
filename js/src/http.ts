/**
 * Small JSON requests for the steps that aren't page visits (fetching
 * WebAuthn options, enrolling). Sends Laravel's XSRF cookie like Inertia does.
 */
export async function json<T = any>(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(xsrf() && { 'X-XSRF-TOKEN': xsrf()! }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  const data = response.status === 204 ? {} : await response.json()

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

function xsrf(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)

  return match ? decodeURIComponent(match[1]) : null
}
