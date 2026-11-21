import { Box, CalendarClock, CircleHelp, Cpu, HardDrive, HeartPulse, RotateCw, ShieldAlert } from 'lucide-react'
import type { Container, ContainerDiagnostics } from '../types/api'
import { formatDate } from '../utils/format'
import { StatusBadge } from './StatusBadge'

type Props = {
  container: Container | undefined
  diagnostics: ContainerDiagnostics | null
}

export function ContainerDetails({ container, diagnostics }: Props) {
  if (!container) {
    return (
      <section className="panel details-panel">
        <div className="empty-state"><CircleHelp size={18} /><span>Select a container to inspect its details.</span></div>
      </section>
    )
  }

  const detailItems = [
    { label: 'Health check', value: diagnostics?.health_status ? <StatusBadge value={diagnostics.health_status} /> : 'Not configured', icon: HeartPulse },
    { label: 'Restart count', value: diagnostics?.restart_count ?? 'Unavailable', icon: RotateCw },
    { label: 'Started at', value: formatDate(diagnostics?.started_at), icon: CalendarClock },
    { label: 'Exit code', value: diagnostics?.running ? '—' : diagnostics?.exit_code ?? 'Unavailable', icon: Box },
    { label: 'OOM killed', value: diagnostics ? (diagnostics.oom_killed ? 'Yes' : 'No') : 'Unavailable', icon: ShieldAlert },
    { label: 'Restart policy', value: diagnostics?.restart_policy || 'Not configured', icon: Cpu },
  ]

  return (
    <section className="panel details-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">SELECTED RESOURCE</p>
          <h2><HardDrive size={17} /> {container.name}</h2>
          <p className="section-description">{container.image} · {container.id}</p>
        </div>
        <StatusBadge value={container.status} />
      </div>
      <div className="detail-grid">
        {detailItems.map(({ label, value, icon: Icon }) => (
          <div className="detail-item" key={label}>
            <Icon size={14} />
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      {diagnostics?.error && <div className="inline-notice notice-error"><ShieldAlert size={14} /> {diagnostics.error}</div>}
    </section>
  )
}
