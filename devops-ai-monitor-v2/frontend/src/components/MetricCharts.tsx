import { Activity, ArrowDownToLine, ArrowUpFromLine, Cpu, MemoryStick } from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatBytes, formatDate, formatPercent } from '../utils/format'
import type { ContainerMetrics, MetricPoint } from '../types/api'

type ChartDatum = {
  time: string
  cpu: number
  memory: number
  networkRx: number
  networkTx: number
}

type Props = {
  metrics: ContainerMetrics | null
  history: MetricPoint[]
  containerName?: string
  loading: boolean
}

function UsageChart({ title, dataKey, color, data, formatter }: {
  title: string
  dataKey: string
  color: string
  data: ChartDatum[]
  formatter: (value: number) => string
}) {
  return (
    <div className="chart-panel">
      <div className="chart-title"><span>{title}</span><span className="chart-live"><i /> Live</span></div>
      <div className="chart-area">
        {data.length < 2 ? (
          <div className="chart-empty"><Activity size={17} /> Collecting metric history</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 6, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id={`fill-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity={0.22} />
                  <stop offset="95%" stopColor={color} stopOpacity={0.01} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#202a36" vertical={false} />
              <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: '#667487', fontSize: 10 }} minTickGap={30} />
              <YAxis tickLine={false} axisLine={false} tick={{ fill: '#667487', fontSize: 10 }} tickFormatter={(value) => formatter(Number(value))} />
              <Tooltip
                contentStyle={{ background: '#111923', border: '1px solid #293544', borderRadius: 8, color: '#e8eef5', fontSize: 12 }}
                labelStyle={{ color: '#91a0b2', marginBottom: 4 }}
                formatter={(value) => [formatter(Number(value)), title]}
              />
              <Area type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} fill={`url(#fill-${dataKey})`} connectNulls={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

function CurrentValue({ icon: Icon, label, value, tone }: {
  icon: typeof Cpu
  label: string
  value: string
  tone: string
}) {
  return (
    <div className="current-value">
      <span className={`current-icon ${tone}`}><Icon size={15} /></span>
      <div><small>{label}</small><strong>{value}</strong></div>
    </div>
  )
}

export function MetricCharts({ metrics, history, containerName, loading }: Props) {
  const data = history.flatMap((point) => point.metrics ? [{
    time: new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    cpu: point.metrics.cpu_percent,
    memory: point.metrics.memory_percent,
    networkRx: point.metrics.network_rx_bytes,
    networkTx: point.metrics.network_tx_bytes,
  }] : [])
  const available = Boolean(metrics)
  const rx = metrics?.network_rx_bytes
  const tx = metrics?.network_tx_bytes

  return (
    <section className="panel metrics-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">LIVE TELEMETRY</p>
          <h2>Resource utilization</h2>
          <p className="section-description">{containerName ? `Selected: ${containerName}` : 'Select a running container to view its metric history.'}</p>
        </div>
        <span className="refresh-label"><i className="pulse-dot" /> Refreshes every 7 seconds</span>
      </div>
      <div className="current-values">
        <CurrentValue icon={Cpu} label="CPU utilization" value={available ? formatPercent(metrics?.cpu_percent) : 'Unavailable'} tone="blue" />
        <CurrentValue icon={MemoryStick} label="Memory utilization" value={available ? formatPercent(metrics?.memory_percent) : 'Unavailable'} tone="violet" />
        <CurrentValue icon={ArrowDownToLine} label="Network received" value={available ? formatBytes(rx) : 'Unavailable'} tone="green" />
        <CurrentValue icon={ArrowUpFromLine} label="Network sent" value={available ? formatBytes(tx) : 'Unavailable'} tone="amber" />
      </div>
      {!available && !loading && <div className="inline-notice">Metrics are unavailable for this container right now. Stopped containers do not expose live metrics.</div>}
      <div className="chart-grid">
        <UsageChart title="CPU utilization" dataKey="cpu" color="#5aa8ff" data={data} formatter={(value) => `${value.toFixed(0)}%`} />
        <UsageChart title="Memory utilization" dataKey="memory" color="#aa8cff" data={data} formatter={(value) => `${value.toFixed(0)}%`} />
        <UsageChart title="Network RX · cumulative" dataKey="networkRx" color="#4bc795" data={data} formatter={formatBytes} />
        <UsageChart title="Network TX · cumulative" dataKey="networkTx" color="#f2b84b" data={data} formatter={formatBytes} />
      </div>
      <div className="network-note">
        <span><ArrowDownToLine size={13} /> RX <b>{available ? formatBytes(rx) : 'Unavailable'}</b></span>
        <span><ArrowUpFromLine size={13} /> TX <b>{available ? formatBytes(tx) : 'Unavailable'}</b></span>
        <p>Docker provides cumulative bytes since the network interfaces were created, not throughput.</p>
      </div>
      <span className="sr-only">Last metric refresh: {formatDate(Date.now())}</span>
    </section>
  )
}
