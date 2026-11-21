import { ChevronRight, History } from 'lucide-react'
import type { Investigation } from '../types/api'
import { formatDate } from '../utils/format'
import { StatusBadge } from './StatusBadge'

type Props = {
  investigations: Investigation[]
  loading: boolean
  selectedId: number | null
  onSelect: (incidentId: number) => void
}

export function InvestigationHistory({ investigations, loading, selectedId, onSelect }: Props) {
  return (
    <section className="panel history-panel">
      <div className="panel-header">
        <div><p className="eyebrow">AUDIT TRAIL</p><h2><History size={18} /> Investigation history</h2></div>
      </div>
      <div className="history-list">
        {investigations.map((item) => (
          <button key={item.id} className={`history-item ${selectedId === item.incident_id ? 'history-selected' : ''}`} onClick={() => onSelect(item.incident_id)}>
            <span className="history-index">#{item.incident_id}</span>
            <span className="history-summary"><strong>{item.summary || `Incident investigation ${item.status}`}</strong><small>{item.model_name || 'Queued'} · {formatDate(item.investigated_at || item.created_at)}</small></span>
            {item.confidence && <span className={`confidence confidence-${item.confidence}`}>{item.confidence}</span>}
            <StatusBadge value={item.status} />
            <ChevronRight size={15} className="history-chevron" />
          </button>
        ))}
        {investigations.length === 0 && <div className="empty-state"><History size={19} /><span>{loading ? 'Loading investigation history…' : 'No investigation history yet.'}</span></div>}
      </div>
    </section>
  )
}
