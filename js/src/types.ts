import type { Purpose } from './routes.js'

/**
 * A sign-in method as the challenge page offers it.
 */
export interface AuthenticatorSummary {
  factor: string
  id: string | null
  name: string
  hint?: string
  remaining?: number
  replace?: boolean
}

/**
 * A sign-in method as a factor presents it everywhere else: in the answer to
 * adding or renaming one, and on your settings page. The dates are ISO 8601.
 * `lastUsedAt` is null until it's first used.
 */
export interface Authenticator extends AuthenticatorSummary {
  createdAt: string | null
  lastUsedAt: string | null
}

/**
 * Why an established sign-in method, or a set of recovery codes, can't be
 * removed or replaced just now, and until when (ISO 8601). It comes with a
 * `422`, as `data.frozen` on the `KeyringRequestError`, beside the usual
 * `message` and `errors.authenticator`. `skip` names the factors that could
 * make the change now (see `proveWithKey()`), and is empty when none can.
 */
export interface FrozenChanges {
  reason: 'new-authenticator' | 'recent-change'
  until: string
  skip: string[]
}

/**
 * A change an established sign-in method can make while the account's
 * sign-in methods are frozen: removing or renaming an authenticator, by
 * its ID, or replacing a factor's, by its key (`recovery` for new recovery
 * codes).
 */
export interface ProvableChange {
  action: 'remove' | 'replace' | 'rename'
  target: string
}

/**
 * What the change's own request sends as `proof`: a key's answer to a
 * challenge for that change, or a code from an authenticator app where
 * the server allows it. `authenticator` names which of the user's
 * authenticators of the factor to check, such as one of two apps. A
 * factor of the app's own reads its answer from its own fields.
 */
export interface FreezeProof {
  factor: string
  authenticator?: string
  credential?: Record<string, any>
  code?: string
  [field: string]: unknown
}

/**
 * Props Keyring sends to the challenge and confirm pages.
 */
export interface ChallengeProps {
  purpose: Purpose
  factor: string
  authenticator: AuthenticatorSummary
  challenge: Record<string, any>
  alternatives: AuthenticatorSummary[]
  canTrustDevice: boolean
  expiresAt: string
}

/**
 * What beginEnrollment() resolves with.
 */
export interface Enrollment {
  factor: string
  enrollment: Record<string, any>
}

/**
 * One of the user's sessions, as listSessions() returns it. `id` is a handle
 * for endSession(), not the session's own ID. It stays the same when the
 * session moves to a new record, and stops matching once the session ends,
 * so list again before ending one from an old list.
 */
export interface Session {
  id: string
  name: string | null
  ip: string | null
  device: string | null
  remembered: boolean
  signedInAt: string
  lastActiveAt: string
  expiresAt: string
  current: boolean
}
