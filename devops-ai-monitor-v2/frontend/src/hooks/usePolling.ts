import { useEffect, useState } from 'react'

export type PollState<T> = {
  data: T | null
  error: string | null
  loading: boolean
  lastUpdated: number | null
  refresh: () => void
}

export function usePolling<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  intervalMs: number,
  dependencies: unknown[] = [],
): PollState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [refreshVersion, setRefreshVersion] = useState(0)

  useEffect(() => {
    let cancelled = false
    let timeout: ReturnType<typeof setTimeout> | undefined
    const controller = new AbortController()

    const poll = async () => {
      try {
        const result = await loader(controller.signal)
        if (!cancelled) {
          setData(result)
          setError(null)
          setLastUpdated(Date.now())
        }
      } catch (pollError) {
        if (!cancelled && !controller.signal.aborted) {
          setError(pollError instanceof Error ? pollError.message : 'Unable to load data')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
          timeout = setTimeout(poll, intervalMs)
        }
      }
    }

    setLoading((current) => current && data === null)
    void poll()

    return () => {
      cancelled = true
      controller.abort()
      if (timeout) clearTimeout(timeout)
    }
    // Loaders are memoized at call sites; extra dependencies control refetches.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, refreshVersion, ...dependencies])

  return {
    data,
    error,
    loading,
    lastUpdated,
    refresh: () => setRefreshVersion((version) => version + 1),
  }
}
