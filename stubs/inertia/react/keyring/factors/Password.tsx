import type { Challenge } from '@entity/keyring/react'

export default function Password({ challenge }: { challenge: Challenge }) {
  const { form } = challenge

  return (
    <form className="space-y-4" onSubmit={e => { e.preventDefault(); challenge.submit() }}>
      <label className="block">
        <span className="text-sm font-medium">Password</span>
        <input type="password" autoComplete="current-password" autoFocus required value={form.data.password} onChange={e => form.setData('password', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
      </label>
      {form.errors.password && <p className="text-sm text-red-600">{form.errors.password}</p>}
      <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Continue</button>
    </form>
  )
}
