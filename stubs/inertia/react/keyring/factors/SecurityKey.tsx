import type { Challenge } from '@entity/keyring/react'
import { useEffect, useRef } from 'react'

export default function SecurityKey({ challenge }: { challenge: Challenge }) {
  const { form, props } = challenge

  const asked = useRef(false)

  // Ask once straight away (StrictMode runs effects twice); the button is
  // there if the user dismissed the prompt.
  useEffect(() => {
    if (!asked.current) {
      asked.current = true
      challenge.verifyKey()
    }
  }, [])

  return (
    <div className="space-y-4 text-center">
      <p className="text-sm">
        {props.factor === 'passkey' ? 'Use your passkey to continue.' : `Insert and tap your security key (${props.authenticator.name}).`}
      </p>
      {form.errors.credential && <p className="text-sm text-red-600">{form.errors.credential}</p>}
      <button type="button" disabled={form.processing} onClick={challenge.verifyKey} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Try again</button>
    </div>
  )
}
