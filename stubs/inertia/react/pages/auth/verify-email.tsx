import { Head, Link, useForm } from '@inertiajs/react'

export default function VerifyEmail({ status }: { status?: string }) {
  const form = useForm({})

  return (
    <>
      <Head title="Verify your email" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Check your email</h1>
        <p className="text-sm">We've sent you a link to verify your email address.</p>
        {status === 'verification-link-sent' && <p className="text-sm text-green-700">A new link is on its way.</p>}

        <button type="button" disabled={form.processing} onClick={() => form.post('/email/verification-notification')} className="w-full rounded-md border px-3 py-2">Send it again</button>

        <Link href="/logout" method="post" as="button" className="w-full text-sm text-gray-600 underline">Sign out</Link>
      </main>
    </>
  )
}
