import type { FactorComponent } from '@entity/keyring/react'
import { lazy } from 'react'

/**
 * One component per factor, shared by the challenge and confirm pages.
 * Adding a factor on the server? Add a line here.
 */
const factors: Record<string, FactorComponent> = {
  'password': lazy(() => import('./factors/Password')),
  'totp': lazy(() => import('./factors/Code')),
  'email-code': lazy(() => import('./factors/Code')),
  'recovery': lazy(() => import('./factors/Code')),
  'passkey': lazy(() => import('./factors/SecurityKey')),
  'security-key': lazy(() => import('./factors/SecurityKey')),
}

export default factors
