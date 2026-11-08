import { Head, Link, useForm } from '@inertiajs/react'

export default function ForgotPassword({ status }: { status?: string }) {
  const form = useForm({ email: '' })

  return (
    <>
      <Head title="Forgot password" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Forgot your password?</h1>
        {status && <p className="text-sm text-green-700">{status}</p>}

        <form className="space-y-4" onSubmit={e => { e.preventDefault(); form.post('/forgot-password') }}>
          <label className="block">
            <span className="text-sm font-medium">Email</span>
            <input type="email" autoComplete="username" autoFocus required value={form.data.email} onChange={e => form.setData('email', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.email && <p className="text-sm text-red-600">{form.errors.email}</p>}

          <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Email me a reset link</button>
        </form>

        <p className="text-center text-sm"><Link href="/login" className="underline">Back to sign in</Link></p>
      </main>
    </>
  )
}
