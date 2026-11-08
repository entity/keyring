import { Head, useForm } from '@inertiajs/react'

export default function DeviceReport({ device, url }: { device: string, url: string }) {
  const form = useForm({})

  return (
    <>
      <Head title="Secure your account" />

      <main className="mx-auto mt-24 max-w-sm space-y-6 px-4">
        <h1 className="text-xl font-semibold">Wasn't you?</h1>
        <p className="text-sm">This signs out {device} and every "remember me" sign-in. Change your password afterwards if you think someone knows it.</p>

        <button type="button" disabled={form.processing} onClick={() => form.post(url)} className="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">
          Sign that device out
        </button>
      </main>
    </>
  )
}
