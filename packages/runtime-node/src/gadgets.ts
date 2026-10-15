/**
 * §3 GHunter neutralization: Node core contains prototype-pollution gadgets
 * (options objects read inherited properties like `shell`, `env`, `input`).
 * Every options object crossing into a granted core API is cloned onto a
 * null-prototype object using bootstrap primordials, so polluted
 * Object.prototype properties can never flow into internal gadget sinks.
 */

const primordials = {
  ObjectCreate: Object.create,
  ReflectOwnKeys: Reflect.ownKeys,
  ReflectGetOwnPropertyDescriptor: Reflect.getOwnPropertyDescriptor,
  ReflectHas: Reflect.has,
}

export function sanitizeGadgetOptions<T extends object>(options?: T): T {
  const clean = primordials.ObjectCreate(null)
  if (options === null || typeof options !== 'object') return clean as T
  const keys = primordials.ReflectOwnKeys(options)
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!
    const desc = primordials.ReflectGetOwnPropertyDescriptor(options, key)
    if (desc && primordials.ReflectHas(desc, 'value')) {
      clean[key as keyof typeof clean] = desc.value
    }
  }
  return clean as T
}

const OPTION_ARG = { spawn: 1, execFile: 1, fork: 1, spawnSync: 1, execFileSync: 1 } as const

/** Wrap granted child_process exports so every options arg is gadget-sanitized. */
export function wrapChildProcess(cp: Record<string, unknown>): Record<string, unknown> {
  const wrapped: Record<string, unknown> = Object.create(null)
  for (const key of Object.keys(cp)) {
    const value = cp[key]
    if (typeof value !== 'function') {
      wrapped[key] = value
      continue
    }
    const optionsIndex = (OPTION_ARG as Record<string, number>)[key]
    if (optionsIndex === undefined) {
      wrapped[key] = value
      continue
    }
    wrapped[key] = function sanitized(...args: unknown[]) {
      if (args[optionsIndex] !== null && typeof args[optionsIndex] === 'object') {
        args[optionsIndex] = sanitizeGadgetOptions(args[optionsIndex] as object)
      }
      return (value as (...a: unknown[]) => unknown).apply(cp, args)
    }
  }
  return wrapped
}
