import { usePasskeyLogin } from '@entity/keyring/react'
import { Head, Link, useForm } from '@inertiajs/react'

export default function Login({ canResetPassword, canRegister, status }: { canResetPassword: boolean, canRegister: boolean, status?: string }) {
  const form = useForm({ email: '', password: '', remember: false })
  const passkey = usePasskeyLogin({ autofill: true, remember: () => form.data.remember })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    form.post('/login', { onFinish: () => form.reset('password') })
  }

  return (
    <>
      <Head title="Sign in" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Sign in</h1>
        {status && <p className="text-sm text-green-700">{status}</p>}

        <form className="space-y-4" onSubmit={submit}>
          <label className="block">
            <span className="text-sm font-medium">Email</span>
            <input type="email" autoComplete="username webauthn" autoFocus required value={form.data.email} onChange={e => form.setData('email', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.email && <p className="text-sm text-red-600">{form.errors.email}</p>}

          <label className="block">
            <span className="flex justify-between text-sm font-medium">
              Password
              {canResetPassword && <Link href="/forgot-password" className="font-normal text-gray-600 underline">Forgot it?</Link>}
            </span>
            <input type="password" autoComplete="current-password" required value={form.data.password} onChange={e => form.setData('password', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>

          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.data.remember} onChange={e => form.setData('remember', e.target.checked)} />
            Remember me
          </label>

          <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Sign in</button>
        </form>

        {passkey.supported && (
          <div className="space-y-2 border-t pt-4">
            <button type="button" disabled={passkey.processing} onClick={passkey.signIn} className="w-full rounded-md border px-3 py-2">Sign in with a passkey</button>
            {passkey.error && <p className="text-sm text-red-600">{passkey.error}</p>}
          </div>
        )}

        {canRegister && <p className="text-center text-sm">New here? <Link href="/register" className="underline">Create an account</Link></p>}
      </main>
    </>
  )
}
