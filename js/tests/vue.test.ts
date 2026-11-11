import { describe, expect, test } from 'bun:test'
import { effectScope, reactive } from 'vue'
import { useChallenge } from '../src/vue'

// Inertia's own useForm, which works without a page. Nothing is replaced
// with mock.module: Bun keeps a module mock for every file that runs after.
describe('vue useChallenge', () => {
  test('is reactive, so factor components can read it without refs', () => {
    const Code = { name: 'Code' }
    const Recovery = { name: 'Recovery' }
    const props = reactive({
      purpose: 'login',
      factor: 'totp',
      authenticator: { factor: 'totp', id: 'a1', name: 'Phone' },
      challenge: {},
      alternatives: [{ factor: 'recovery', id: 'r1', name: 'Recovery codes' }],
      canTrustDevice: true,
      expiresAt: '2026-11-08T12:00:00Z',
    }) as any

    effectScope().run(() => {
      const challenge = useChallenge(props, { totp: Code, recovery: Recovery })

      expect(challenge.component).toBe(Code)
      expect(challenge.props.authenticator.name).toBe('Phone')
      expect(challenge.form.code).toBe('')

      props.factor = 'recovery'

      expect(challenge.component).toBe(Recovery)
    })
  })
})
