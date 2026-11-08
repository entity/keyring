import { useChallenge, type ChallengeProps } from '@entity/keyring/react'
import { Head } from '@inertiajs/react'
import { Suspense, useState } from 'react'
import factors from '../../keyring/factors'

export default function ChallengePage(props: ChallengeProps) {
  const challenge = useChallenge(props, factors)
  const [showingAlternatives, setShowingAlternatives] = useState(false)
  const { form } = challenge

  // A factor with no component yet gets the closest built-in one.
  const Component = challenge.Component ?? (props.challenge.options ? factors['security-key'] : factors.totp)

  return (
    <>
      <Head title={props.purpose === 'login' ? 'Verify it\'s you' : 'Confirm it\'s you'} />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">{props.purpose === 'login' ? 'One more step' : 'Confirm it\'s you'}</h1>

        <Suspense fallback={null}>
          <Component key={`${props.factor}:${props.authenticator.id}`} challenge={challenge} />
        </Suspense>

        {props.canTrustDevice && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.data.trust} onChange={e => form.setData('trust', e.target.checked)} />
            Don't ask again on this device
          </label>
        )}

        {props.alternatives.length > 0 && (
          <div className="border-t pt-4">
            <button type="button" onClick={() => setShowingAlternatives(!showingAlternatives)} className="text-sm text-gray-600 underline">Try another way</button>

            {showingAlternatives && (
              <ul className="mt-3 space-y-2">
                {props.alternatives.map(option => (
                  <li key={`${option.factor}:${option.id}`}>
                    <button type="button" onClick={() => challenge.switchTo(option)} className="w-full rounded-md border px-3 py-2 text-left text-sm hover:bg-gray-50">
                      {option.name}
                      {option.hint && <span className="block text-xs text-gray-500">{option.hint}</span>}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </main>
    </>
  )
}
