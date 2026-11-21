import { Search, Server, ArrowUpRight } from 'lucide-react'
import { useMemo, useState } from 'react'
import { StatusBadge } from './StatusBadge'
import type { Container, ContainerDiagnostics, ContainerMetrics } from '../types/api'
import { formatDate, formatPercent, shortId } from '../utils/format'

type Props = {
  containers: Container[]
  metrics: Record<string, ContainerMetrics | null>
  diagnostics: Record<string, ContainerDiagnostics | null>
  selectedId: string | null
  lastUpdated: number | null
  loading: boolean
  onSelect: (id: string) => void
}

export function ContainerTable({ containers, metrics, diagnostics, selectedId, lastUpdated, loading, onSelect }: Props) {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const filtered = useMemo(() => containers.filter((container) => {
    const matchesText = `${container.name} ${container.id} ${container.image}`.toLowerCase().includes(search.toLowerCase())
    return matchesText && (statusFilter === 'all' || container.status.toLowerCase() === statusFilter)
  }), [containers, search, statusFilter])

  return (
    <section className="panel">
      <div className="panel-header table-panel-header">
        <div>
          <p className="eyebrow">DOCKER ENGINE</p>
          <h2>Containers <span className="count-chip">{containers.length}</span></h2>
          <p className="section-description">Infrastructure inventory and current resource usage.</p>
        </div>
        <div className="table-controls">
          <label className="search-field"><Search size={15} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search containers" /></label>
          <select aria-label="Filter containers by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All statuses</option>
            <option value="running">Running</option>
            <option value="exited">Stopped</option>
            <option value="paused">Paused</option>
          </select>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Container</th><th>Status</th><th>Health</th><th>CPU</th><th>Memory</th><th>Restarts</th><th>Last updated</th><th /></tr></thead>
          <tbody>
            {filtered.map((container) => {
              const metric = metrics[container.id]
              const detail = diagnostics[container.id]
              return (
                <tr key={container.id} className={selectedId === container.id ? 'selected-row' : ''} onClick={() => onSelect(container.id)}>
                  <td>
                    <div className="container-cell"><span className="container-symbol"><Server size={15} /></span><span><strong>{container.name}</strong><small>{shortId(container.id)} · {container.image}</small></span></div>
                  </td>
                  <td><StatusBadge value={container.status} /></td>
                  <td>{detail?.health_status ? <StatusBadge value={detail.health_status} /> : <span className="muted-text">Not configured</span>}</td>
                  <td><MetricCell value={metric?.cpu_percent} /></td>
                  <td><MetricCell value={metric?.memory_percent} /></td>
                  <td className="numeric-cell">{detail?.restart_count ?? '—'}</td>
                  <td className="date-cell">{container.status === 'running' && metric ? formatDate(lastUpdated) : 'Unavailable'}</td>
                  <td><button className="icon-button row-open" aria-label={`View ${container.name}`} onClick={(event) => { event.stopPropagation(); onSelect(container.id) }}><ArrowUpRight size={15} /></button></td>
                </tr>
              )
            })}
            {filtered.length === 0 && <tr><td colSpan={8}><div className="empty-state"><Server size={20} /><span>{loading ? 'Loading Docker inventory…' : containers.length ? 'No containers match your filters.' : 'No containers returned by Docker.'}</span></div></td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function MetricCell({ value }: { value?: number }) {
  if (value === undefined) return <span className="muted-text">Unavailable</span>
  const tone = value >= 95 ? 'metric-danger' : value >= 80 ? 'metric-warning' : 'metric-good'
  return <span className={`metric-cell ${tone}`}>{formatPercent(value)}</span>
}
