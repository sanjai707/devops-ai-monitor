import { Activity, CircleAlert, CircleCheck, CircleDashed, CircleX } from 'lucide-react'

type Props = {
  value: string | null | undefined
}

export function StatusBadge({ value }: Props) {
  const status = (value || 'unknown').toLowerCase()
  const styles: Record<string, string> = {
    running: 'badge badge-green',
    healthy: 'badge badge-green',
    open: 'badge badge-red',
    critical: 'badge badge-red',
    exited: 'badge badge-slate',
    dead: 'badge badge-slate',
    resolved: 'badge badge-slate',
    acknowledged: 'badge badge-blue',
    warning: 'badge badge-amber',
    unhealthy: 'badge badge-red',
    pending: 'badge badge-amber',
    processing: 'badge badge-blue',
    completed: 'badge badge-green',
    failed: 'badge badge-red',
    unknown: 'badge badge-slate',
    paused: 'badge badge-amber',
    restarting: 'badge badge-amber',
  }
  const icons: Record<string, typeof Activity> = {
    running: CircleCheck,
    healthy: CircleCheck,
    completed: CircleCheck,
    critical: CircleAlert,
    open: CircleAlert,
    unhealthy: CircleX,
    failed: CircleX,
    pending: CircleDashed,
    processing: Activity,
  }
  const Icon = icons[status] || Activity

  return (
    <span className={styles[status] || styles.unknown}>
      <Icon size={13} strokeWidth={2.2} />
      {status}
    </span>
  )
}
