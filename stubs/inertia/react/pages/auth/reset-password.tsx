import { Head, useForm } from '@inertiajs/react'

export default function ResetPassword({ token, email }: { token: string, email: string }) {
  const form = useForm({ token, email, password: '', password_confirmation: '' })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    form.post('/reset-password', { onFinish: () => form.reset('password', 'password_confirmation') })
  }

  return (
    <>
      <Head title="Reset password" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Choose a new password</h1>

        <form className="space-y-4" onSubmit={submit}>
          <label className="block">
            <span className="text-sm font-medium">Email</span>
            <input type="email" autoComplete="username" required value={form.data.email} onChange={e => form.setData('email', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.email && <p className="text-sm text-red-600">{form.errors.email}</p>}

          <label className="block">
            <span className="text-sm font-medium">New password</span>
            <input type="password" autoComplete="new-password" autoFocus required value={form.data.password} onChange={e => form.setData('password', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.password && <p className="text-sm text-red-600">{form.errors.password}</p>}

          <label className="block">
            <span className="text-sm font-medium">Confirm new password</span>
            <input type="password" autoComplete="new-password" required value={form.data.password_confirmation} onChange={e => form.setData('password_confirmation', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>

          <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Reset password</button>
        </form>
      </main>
    </>
  )
}
