import { useContext, useSyncExternalStore } from 'react'

import { ClockOffsetContext } from './context'

/// One shared one-second ticker. A page can show a hundred countdowns, and a hundred
/// intervals drifting against each other would make them visibly disagree.
const listeners = new Set<() => void>()
let timer: ReturnType<typeof setInterval> | undefined
let now = Date.now()

function subscribe(listener: () => void) {
  listeners.add(listener)
  if (!timer) {
    now = Date.now()
    timer = setInterval(() => {
      now = Date.now()
      for (const l of listeners) l()
    }, 1000)
  }
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0 && timer) {
      clearInterval(timer)
      timer = undefined
    }
  }
}

/// The simulator's current time, in milliseconds, re-rendering every second.
export function useSimNow(): number {
  const offset = useContext(ClockOffsetContext)
  const browserNow = useSyncExternalStore(subscribe, () => now)
  return browserNow + offset
}

/// "in 54 min", "3 min ago". Coarse on purpose: the exact second matters only near zero.
export function relative(ms: number): string {
  const abs = Math.abs(ms)
  const s = Math.round(abs / 1000)
  let text: string
  if (s < 60) text = `${s} s`
  else if (s < 3600) text = `${Math.floor(s / 60)} min${s < 600 ? ` ${s % 60} s` : ''}`
  else if (s < 86400) text = `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
  else if (s < 86400 * 365) text = `${Math.floor(s / 86400)} d`
  else text = `${(s / (86400 * 365)).toFixed(1)} y`
  return ms >= 0 ? `in ${text}` : `${text} ago`
}

export const MINUTE = 60_000
export const DAY = 86_400_000
