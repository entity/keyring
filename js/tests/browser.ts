/**
 * Stand in for the globals a browser would have, for the length of a test.
 *
 * Every test file runs in the one process, in whatever order Bun finds the
 * files, so anything left on globalThis is still there for the next file.
 * Call the function this returns in afterEach: it puts back what was there
 * before (Bun has a fetch and a navigator of its own) and removes the rest.
 */
export function standIn(globals: Record<string, unknown>): () => void {
  const before = Object.keys(globals).map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)] as const)

  for (const [name, value] of Object.entries(globals)) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true })
  }

  return () => {
    for (const [name, descriptor] of before) {
      if (descriptor) {
        Object.defineProperty(globalThis, name, descriptor)
      } else {
        delete (globalThis as any)[name]
      }
    }
  }
}
