/**
 * WebAuthn in the browser: turn Keyring's JSON options into what
 * navigator.credentials expects, and the result back into JSON.
 */

type Json = Record<string, any>

export function supportsWebAuthn(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window
}

/**
 * Whether the browser can offer passkeys in the email field's autofill.
 */
export async function supportsAutofill(): Promise<boolean> {
  return supportsWebAuthn()
    && typeof PublicKeyCredential.isConditionalMediationAvailable === 'function'
    && PublicKeyCredential.isConditionalMediationAvailable()
}

/**
 * Run navigator.credentials.create() with options from enrollment.
 */
export async function createCredential(options: Json): Promise<Json> {
  ensureSupported()

  const publicKey = 'parseCreationOptionsFromJSON' in PublicKeyCredential
    ? PublicKeyCredential.parseCreationOptionsFromJSON(options as PublicKeyCredentialCreationOptionsJSON)
    : {
        ...options,
        challenge: fromBase64Url(options.challenge),
        user: { ...options.user, id: fromBase64Url(options.user.id) },
        excludeCredentials: (options.excludeCredentials ?? []).map(descriptor),
      } as PublicKeyCredentialCreationOptions

  return toJson(await navigator.credentials.create({ publicKey }))
}

/**
 * Run navigator.credentials.get() with options from a challenge or login.
 * Pass `autofill: true` to show passkeys in the browser's autofill instead
 * of a modal (the input needs autocomplete="username webauthn").
 */
export async function getCredential(options: Json, { autofill = false, signal }: { autofill?: boolean, signal?: AbortSignal } = {}): Promise<Json> {
  ensureSupported()

  const publicKey = 'parseRequestOptionsFromJSON' in PublicKeyCredential
    ? PublicKeyCredential.parseRequestOptionsFromJSON(options as PublicKeyCredentialRequestOptionsJSON)
    : {
        ...options,
        challenge: fromBase64Url(options.challenge),
        allowCredentials: (options.allowCredentials ?? []).map(descriptor),
      } as PublicKeyCredentialRequestOptions

  return toJson(await navigator.credentials.get({ publicKey, mediation: autofill ? 'conditional' : undefined, signal }))
}

function ensureSupported(): void {
  if (!supportsWebAuthn()) {
    throw new Error('This browser does not support passkeys or security keys.')
  }
}

function toJson(credential: Credential | null): Json {
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error('No passkey or security key was used.')
  }

  if (typeof credential.toJSON === 'function') {
    return credential.toJSON()
  }

  const response = credential.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse

  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      ...('attestationObject' in response && {
        attestationObject: toBase64Url(response.attestationObject),
        transports: response.getTransports?.() ?? [],
      }),
      ...('signature' in response && {
        authenticatorData: toBase64Url(response.authenticatorData),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
      }),
    },
  }
}

function descriptor(credential: Json): PublicKeyCredentialDescriptor {
  return { ...credential, id: fromBase64Url(credential.id) } as PublicKeyCredentialDescriptor
}

export function toBase64Url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')

  return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer
}
