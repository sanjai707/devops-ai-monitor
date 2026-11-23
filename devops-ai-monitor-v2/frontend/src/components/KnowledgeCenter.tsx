import { BookOpenCheck, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { KnowledgeRecord } from '../types/api'

type Props = {
  records: KnowledgeRecord[]
  loading: boolean
  busyId: number | null
  onApprove: (id: number) => void
  onReject: (id: number) => void
  onDeprecate: (id: number) => void
}

export function KnowledgeCenter({ records, loading, busyId, onApprove, onReject, onDeprecate }: Props) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return records
    return records.filter((record) =>
      [record.title, record.content, record.category, record.source, ...record.tags]
        .join(' ')
        .toLowerCase()
        .includes(needle),
    )
  }, [query, records])

  return (
    <section className="panel knowledge-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">PERSISTENT OPERATIONAL MEMORY</p>
          <h2><BookOpenCheck size={18} /> Knowledge Center</h2>
        </div>
        <label className="search-field">
          <Search size={14} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search approved knowledge" />
        </label>
      </div>
      <div className="knowledge-list">
        {filtered.map((record) => (
          <article className="knowledge-item" key={record.id}>
            <div>
              <strong>{record.title}</strong>
              <small>{record.category} · {record.source} · v{record.version}</small>
              <p>{record.content}</p>
              <div className="knowledge-tags">{record.tags.map((tag) => <span key={tag}>{tag}</span>)}</div>
            </div>
            <div className="knowledge-actions">
              <StatusBadge status={record.approval_status} />
              {record.approval_status !== 'approved' && <button disabled={busyId === record.id} onClick={() => onApprove(record.id)}>Approve</button>}
              {record.approval_status !== 'rejected' && <button disabled={busyId === record.id} onClick={() => onReject(record.id)}>Reject</button>}
              {record.approval_status !== 'deprecated' && <button disabled={busyId === record.id} onClick={() => onDeprecate(record.id)}>Deprecate</button>}
            </div>
          </article>
        ))}
        {filtered.length === 0 && <div className="empty-state"><BookOpenCheck size={18} /><span>{loading ? 'Loading knowledge…' : 'No knowledge records match.'}</span></div>}
      </div>
    </section>
  )
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status.replace(/[^a-z0-9]+/gi, '-')}`}>{status.replaceAll('_', ' ')}</span>
}
