import { Check, CheckCheck, Filter, ShieldAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { Incident } from '../types/api'
import { formatDate } from '../utils/format'
import { StatusBadge } from './StatusBadge'

type Props = {
  incidents: Incident[]
  loading: boolean
  selectedId: number | null
  busyId: number | null
  onSelect: (incident: Incident) => void
  onAcknowledge: (id: number) => void
  onResolve: (id: number) => void
}

export function IncidentCenter({ incidents, loading, selectedId, busyId, onSelect, onAcknowledge, onResolve }: Props) {
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('active')
  const activeCount = incidents.filter((incident) => incident.status !== 'resolved').length
  const filtered = useMemo(() => incidents.filter((incident) => {
    const severityMatch = severityFilter === 'all' || incident.severity === severityFilter
    const statusMatch = statusFilter === 'all' || (statusFilter === 'active' ? incident.status !== 'resolved' : incident.status === statusFilter)
    return severityMatch && statusMatch
  }), [incidents, severityFilter, statusFilter])

  return (
    <section className="panel">
      <div className="panel-header table-panel-header">
        <div>
          <p className="eyebrow">ALERT MANAGEMENT</p>
          <h2>Incident center <span className={`count-chip ${activeCount ? 'count-alert' : ''}`}>{activeCount} active</span></h2>
          <p className="section-description">Review evidence, acknowledge alerts, and track resolution.</p>
        </div>
        <div className="table-controls">
          <label className="select-with-icon"><Filter size={14} /><select aria-label="Filter incidents by severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severity</option><option value="critical">Critical</option><option value="warning">Warning</option></select></label>
          <select aria-label="Filter incidents by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="active">Active</option><option value="all">All incidents</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Created</th><th>Acknowledgement</th><th>Actions</th></tr></thead>
          <tbody>
            {filtered.map((incident) => (
              <tr key={incident.id} className={selectedId === incident.id ? 'selected-row' : ''} onClick={() => onSelect(incident)}>
                <td><button className="incident-title-button" onClick={(event) => { event.stopPropagation(); onSelect(incident) }}><span className={`severity-mark ${incident.severity}`} /><span><strong>{incident.title}</strong><small>#{incident.id} · {incident.container_name} · {incident.type}</small></span></button></td>
                <td><StatusBadge value={incident.severity} /></td>
                <td><StatusBadge value={incident.status} /></td>
                <td className="date-cell">{formatDate(incident.created_at)}</td>
                <td>{incident.acknowledged_at ? <span className="acknowledged-label"><Check size={13} /> Acknowledged</span> : <span className="muted-text">Awaiting review</span>}</td>
                <td>
                  <div className="row-actions">
                    {incident.status === 'open' && <button className="small-action" disabled={busyId === incident.id} onClick={(event) => { event.stopPropagation(); onAcknowledge(incident.id) }}><Check size={13} /> Ack</button>}
                    {incident.status !== 'resolved' && <button className="small-action resolve-action" disabled={busyId === incident.id} onClick={(event) => { event.stopPropagation(); onResolve(incident.id) }}><CheckCheck size={13} /> Resolve</button>}
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={6}><div className="empty-state"><ShieldAlert size={20} /><span>{loading ? 'Loading incident records…' : incidents.length ? 'No incidents match these filters.' : 'No incidents recorded. Monitoring is active.'}</span></div></td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
