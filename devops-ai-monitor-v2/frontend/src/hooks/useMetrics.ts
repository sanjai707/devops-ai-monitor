import { useEffect, useState } from 'react'
import { api } from '../services/api'
import type { Container, ContainerMetrics, MetricPoint } from '../types/api'

const HISTORY_LIMIT = 48

export function useMetrics(containers: Container[], containerKey: string) {
  const [metrics, setMetrics] = useState<Record<string, ContainerMetrics | null>>({})
  const [history, setHistory] = useState<Record<string, MetricPoint[]>>({})
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)

  useEffect(() => {
    let cancelled = false
    let timeout: ReturnType<typeof setTimeout> | undefined
    let controller: AbortController | null = null

    const poll = async () => {
      controller = new AbortController()
      const running = containers.filter((container) => container.status === 'running')
      const results: Array<readonly [string, ContainerMetrics | null]> = []
      for (const container of running) {
        try {
          results.push([container.id, await api.metrics(container.id, controller.signal)])
        } catch {
          results.push([container.id, null])
        }
      }

      if (!cancelled) {
        const next: Record<string, ContainerMetrics | null> = {}
        for (const [id, value] of results) next[id] = value
        setMetrics(next)
        const timestamp = Date.now()
        setHistory((previous) => {
          const updated = { ...previous }
          for (const container of running) {
            updated[container.id] = [
              ...(previous[container.id] || []),
              { timestamp, metrics: next[container.id] ?? null },
            ].slice(-HISTORY_LIMIT)
          }
          return updated
        })
        setLastUpdated(timestamp)
        setLoading(false)
        timeout = setTimeout(poll, 7000)
      }
    }

    setMetrics((current) => {
      const runningIds = new Set(containers.filter((container) => container.status === 'running').map((item) => item.id))
      return Object.fromEntries(Object.entries(current).filter(([id]) => runningIds.has(id)))
    })
    void poll()

    return () => {
      cancelled = true
      controller?.abort()
      if (timeout) clearTimeout(timeout)
    }
  // containerKey changes only when the running inventory changes, not on each parent render.
  }, [containerKey])

  return { metrics, history, loading, lastUpdated }
}
