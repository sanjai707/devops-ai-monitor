import type { LucideIcon } from 'lucide-react'

type Props = {
  label: string
  value: number | string
  detail: string
  icon: LucideIcon
  tone: 'blue' | 'green' | 'amber' | 'red'
}

export function MetricCard({ label, value, detail, icon: Icon, tone }: Props) {
  return (
    <article className="metric-card">
      <div className={`metric-icon metric-icon-${tone}`}><Icon size={18} /></div>
      <div className="metric-card-copy">
        <p>{label}</p>
        <strong>{value}</strong>
        <span>{detail}</span>
      </div>
    </article>
  )
}
