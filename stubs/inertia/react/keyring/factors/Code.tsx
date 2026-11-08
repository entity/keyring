import type { Challenge } from '@entity/keyring/react'

export default function Code({ challenge }: { challenge: Challenge }) {
  const { form, props } = challenge

  const copy = {
    'totp': { label: 'Code from your authenticator app', hint: props.authenticator.name, inputMode: 'numeric' as const },
    'email-code': { label: 'Code from your email', hint: props.authenticator.hint, inputMode: 'numeric' as const },
    'recovery': { label: 'Recovery code', hint: `${props.authenticator.remaining ?? 0} left`, inputMode: 'text' as const },
  }[props.factor] ?? { label: 'Code', hint: undefined, inputMode: 'text' as const }

  const needsSending = props.factor === 'email-code'

  if (needsSending && !props.challenge.sent) {
    return (
      <div className="space-y-2">
        <p className="text-sm">We'll email a code to {props.authenticator.hint}.</p>
        <button type="button" onClick={challenge.send} className="w-full rounded-md bg-black px-3 py-2 text-white">Send code</button>
      </div>
    )
  }

  return (
    <form className="space-y-4" onSubmit={e => { e.preventDefault(); challenge.submit() }}>
      <label className="block">
        <span className="text-sm font-medium">{copy.label}</span>
        {copy.hint && <span className="block text-xs text-gray-500">{copy.hint}</span>}
        <input inputMode={copy.inputMode} autoComplete="one-time-code" autoFocus required value={form.data.code} onChange={e => form.setData('code', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2 tracking-widest" />
      </label>
      {form.errors.code && <p className="text-sm text-red-600">{form.errors.code}</p>}
      <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Verify</button>
      {needsSending && <button type="button" onClick={challenge.send} className="w-full text-sm text-gray-600 underline">Send a new code</button>}
    </form>
  )
}
