import type { Challenge } from '@entity/keyring/react'
import { useEffect } from 'react'

export default function SecurityKey({ challenge }: { challenge: Challenge }) {
  const { form, props } = challenge

  // Ask straight away; the button is there if the user dismissed the prompt.
  useEffect(() => { challenge.useKey() }, [])

  return (
    <div className="space-y-4 text-center">
      <p className="text-sm">
        {props.factor === 'passkey' ? 'Use your passkey to continue.' : `Insert and tap your security key (${props.authenticator.name}).`}
      </p>
      {form.errors.credential && <p className="text-sm text-red-600">{form.errors.credential}</p>}
      <button type="button" disabled={form.processing} onClick={challenge.useKey} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Try again</button>
    </div>
  )
}
