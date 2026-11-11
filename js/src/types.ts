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
 * for endSession(), not the session's own ID, and changes when the session
 * moves to a new record, so list again before ending one from an old list.
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
