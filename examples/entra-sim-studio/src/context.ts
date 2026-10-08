import { createContext, useContext } from 'react'

import type { Directory } from './directory'

/// The cross-referenced snapshot, so any component can turn a GUID into a name without it
/// being threaded through every table.
export const DirectoryContext = createContext<Directory | null>(null)

export function useDirectory(): Directory {
  const directory = useContext(DirectoryContext)
  if (!directory) throw new Error('useDirectory outside DirectoryContext')
  return directory
}

/// Simulator clock minus browser clock, in milliseconds. See `SimState.clockOffsetMs`.
export const ClockOffsetContext = createContext(0)
