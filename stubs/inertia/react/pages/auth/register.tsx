import { Head, Link, useForm } from '@inertiajs/react'

export default function Register() {
  const form = useForm({ name: '', email: '', password: '', password_confirmation: '' })

  function submit(e: React.FormEvent) {
    e.preventDefault()
    form.post('/register', { onFinish: () => form.reset('password', 'password_confirmation') })
  }

  return (
    <>
      <Head title="Create an account" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Create an account</h1>

        <form className="space-y-4" onSubmit={submit}>
          <label className="block">
            <span className="text-sm font-medium">Name</span>
            <input autoComplete="name" autoFocus required value={form.data.name} onChange={e => form.setData('name', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.name && <p className="text-sm text-red-600">{form.errors.name}</p>}

          <label className="block">
            <span className="text-sm font-medium">Email</span>
            <input type="email" autoComplete="username" required value={form.data.email} onChange={e => form.setData('email', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.email && <p className="text-sm text-red-600">{form.errors.email}</p>}

          <label className="block">
            <span className="text-sm font-medium">Password</span>
            <span className="block text-xs text-gray-500">Long beats complicated. A few random words works well.</span>
            <input type="password" autoComplete="new-password" required value={form.data.password} onChange={e => form.setData('password', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>
          {form.errors.password && <p className="text-sm text-red-600">{form.errors.password}</p>}

          <label className="block">
            <span className="text-sm font-medium">Confirm password</span>
            <input type="password" autoComplete="new-password" required value={form.data.password_confirmation} onChange={e => form.setData('password_confirmation', e.target.value)} className="mt-1 w-full rounded-md border px-3 py-2" />
          </label>

          <button type="submit" disabled={form.processing} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Create account</button>
        </form>

        <p className="text-center text-sm">Already have an account? <Link href="/login" className="underline">Sign in</Link></p>
      </main>
    </>
  )
}
