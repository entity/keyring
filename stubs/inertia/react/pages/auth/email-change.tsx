import { Head, useForm } from '@inertiajs/react'

export default function EmailChange({ action, url }: { action: 'confirm' | 'revert', url: string }) {
  const form = useForm({})

  return (
    <>
      <Head title={action === 'confirm' ? 'Confirm email change' : 'Secure your account'} />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        {action === 'confirm' ? (
          <>
            <h1 className="text-xl font-semibold">Confirm your email change</h1>
            <p className="text-sm">Press the button to confirm this change to your account's email address.</p>
          </>
        ) : (
          <>
            <h1 className="text-xl font-semibold">Wasn't you?</h1>
            <p className="text-sm">This puts your old email address back, removes sign-in methods added since the change, and signs out every device.</p>
          </>
        )}

        <button type="button" disabled={form.processing} onClick={() => form.post(url)} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">
          {action === 'confirm' ? 'Confirm change' : 'Undo the change and secure my account'}
        </button>
      </main>
    </>
  )
}
