import { describe, expect, mock, test } from 'bun:test'
import { effectScope, reactive } from 'vue'

mock.module('@inertiajs/vue3', () => ({
  useForm: (fields: Record<string, unknown>) => reactive({ ...fields, errors: {}, processing: false, clearErrors() {}, setError() {} }),
}))

mock.module('@inertiajs/core', () => ({ router: { get: () => {}, post: () => {} } }))

const { useChallenge } = await import('../src/vue')

const props = reactive({
  purpose: 'login',
  factor: 'totp',
  authenticator: { factor: 'totp', id: 'a1', name: 'Phone' },
  challenge: {},
  alternatives: [{ factor: 'recovery', id: 'r1', name: 'Recovery codes' }],
  canTrustDevice: true,
  expiresAt: '2026-11-08T12:00:00Z',
}) as any

describe('vue useChallenge', () => {
  test('is reactive, so factor components can read it without refs', () => {
    const Code = { name: 'Code' }
    const Recovery = { name: 'Recovery' }

    effectScope().run(() => {
      const challenge = useChallenge(props, { totp: Code, recovery: Recovery })

      expect(challenge.component).toBe(Code)
      expect(challenge.alternatives).toHaveLength(1)
      expect(challenge.props.authenticator.name).toBe('Phone')
      expect(challenge.form.code).toBe('')

      props.factor = 'recovery'

      expect(challenge.component).toBe(Recovery)
    })
  })
})
