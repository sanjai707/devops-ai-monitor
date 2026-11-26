import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Box,
  BrainCircuit,
  CheckCircle2,
  Container as ContainerIcon,
  Cpu,
  HardDrive,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
  Zap,
  BookOpenCheck,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { ContainerTable } from './components/ContainerTable'
import { ContainerDetails } from './components/ContainerDetails'
import { IncidentCenter } from './components/IncidentCenter'
import { InvestigationHistory } from './components/InvestigationHistory'
import { InvestigationPanel } from './components/InvestigationPanel'
import { KnowledgeCenter } from './components/KnowledgeCenter'
import { MetricCard } from './components/MetricCard'
import { MetricCharts } from './components/MetricCharts'
import { SectionHeading } from './components/SectionHeading'
import { StatusBadge } from './components/StatusBadge'
import { useMetrics } from './hooks/useMetrics'
import { usePolling } from './hooks/usePolling'
import { api } from './services/api'
import type {
  ContainerDiagnostics,
  Investigation,
  MetricHistoryResponse,
  FollowupActionId,
} from './types/api'
import { formatDate } from './utils/format'

const navigation = [
  { label: 'Overview', href: '#overview', icon: Activity },
  { label: 'Infrastructure', href: '#infrastructure', icon: Server },
  { label: 'Incident center', href: '#incidents', icon: ShieldAlert },
  { label: 'AI investigations', href: '#investigations', icon: BrainCircuit },
  { label: 'Knowledge Center', href: '#knowledge', icon: BookOpenCheck },
]

export default function App() {
  const loadHealth = useCallback((signal: AbortSignal) => api.health(signal), [])
  const loadContainers = useCallback((signal: AbortSignal) => api.containers(signal), [])
  const loadMonitor = useCallback((signal: AbortSignal) => api.monitorStatus(signal), [])
  const loadIncidents = useCallback((signal: AbortSignal) => api.incidents(signal), [])
  const loadInvestigations = useCallback((signal: AbortSignal) => api.investigations(signal), [])
  const loadInvestigationStatus = useCallback((signal: AbortSignal) => api.investigationStatus(signal), [])
  const loadKnowledge = useCallback((signal: AbortSignal) => api.knowledge(signal), [])

  const healthState = usePolling(loadHealth, 10_000)
  const containersState = usePolling(loadContainers, 10_000)
  const monitorState = usePolling(loadMonitor, 10_000)
  const incidentsState = usePolling(loadIncidents, 10_000)
  const investigationsState = usePolling(loadInvestigations, 10_000)
  const queueState = usePolling(loadInvestigationStatus, 5_000)
  const knowledgeState = usePolling(loadKnowledge, 15_000)

  const containers = containersState.data || []
  const incidents = incidentsState.data || []
  const investigations = investigationsState.data || []
  const runningContainers = containers.filter((container) => container.status.toLowerCase() === 'running')
  const containerKey = containers.map((container) => `${container.id}:${container.status}`).join('|')
  const metricState = useMetrics(containers, containerKey)

  const diagnosticsLoader = useCallback(async (signal: AbortSignal) => {
    const records = await Promise.all(
      containers.map(async (container) => {
        try {
          return [container.id, await api.diagnostics(container.id, signal)] as const
        } catch {
          return [container.id, null] as const
        }
      }),
    )
    return Object.fromEntries(records) as Record<string, ContainerDiagnostics | null>
  }, [containerKey])
  const diagnosticsState = usePolling(diagnosticsLoader, 10_000, [containerKey])

  const [selectedContainerId, setSelectedContainerId] = useState<string | null>(null)
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null)
  const [busyIncidentId, setBusyIncidentId] = useState<number | null>(null)
  const [manualBusy, setManualBusy] = useState(false)
  const [knowledgeBusyId, setKnowledgeBusyId] = useState<number | null>(null)
  const [followupBusyId, setFollowupBusyId] = useState<FollowupActionId | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const selectedIncident = incidents.find((incident) => incident.id === selectedIncidentId) || null

  useEffect(() => {
    if (!selectedContainerId && runningContainers.length) {
      setSelectedContainerId(runningContainers[0].id)
    } else if (selectedContainerId && !containers.some((container) => container.id === selectedContainerId)) {
      setSelectedContainerId(runningContainers[0]?.id || containers[0]?.id || null)
    }
  }, [containerKey, selectedContainerId])

  useEffect(() => {
    if (incidents.length === 0) {
      if (selectedIncidentId !== null) setSelectedIncidentId(null)
      return
    }
    if (!selectedIncidentId && incidents.length) {
      const active = incidents.find((incident) => incident.status !== 'resolved')
      setSelectedIncidentId((active || incidents[0]).id)
    } else if (selectedIncidentId && !incidents.some((item) => item.id === selectedIncidentId)) {
      setSelectedIncidentId(incidents[0]?.id || null)
    }
  }, [incidents, selectedIncidentId])

  const incidentLoader = useCallback((signal: AbortSignal) => {
    if (!selectedIncidentId) return Promise.resolve(null)
    return api.investigation(selectedIncidentId, signal)
  }, [selectedIncidentId])
  const selectedInvestigationState = usePolling<Investigation | null>(
    incidentLoader,
    5_000,
    [selectedIncidentId],
  )
  const followupLoader = useCallback(
    (signal: AbortSignal) => selectedIncidentId
      ? api.investigationFollowups(selectedIncidentId, signal)
      : Promise.resolve([]),
    [selectedIncidentId],
  )
  const followupState = usePolling(followupLoader, 5_000, [selectedIncidentId])
  const displayedInvestigation = selectedInvestigationState.data?.incident_id === selectedIncidentId
    ? selectedInvestigationState.data
    : null

  const selectedMetrics = selectedContainerId ? metricState.metrics[selectedContainerId] || null : null
  const selectedContainer = containers.find((container) => container.id === selectedContainerId)
  const selectedHistory = selectedContainerId ? metricState.history[selectedContainerId] || [] : []
  const metricHistoryLoader = useCallback(
    (signal: AbortSignal) => selectedContainerId
      ? api.metricHistory(selectedContainerId, 60, signal)
      : Promise.resolve(null),
    [selectedContainerId],
  )
  const persistedMetricHistoryState = usePolling<MetricHistoryResponse | null>(
    metricHistoryLoader,
    10_000,
    [selectedContainerId],
  )

  const unhealthyCount = Object.values(diagnosticsState.data || {}).filter((item) => item?.health_status === 'unhealthy').length
  const activeIncidents = incidents.filter((incident) =>
    !['resolved', 'suppressed'].includes(incident.status),
  )
  const criticalIncidents = activeIncidents.filter((incident) => incident.severity === 'critical')
  const stoppedCount = containers.filter((container) => container.status.toLowerCase() !== 'running').length
  const lastRefresh = Math.max(
    healthState.lastUpdated || 0,
    containersState.lastUpdated || 0,
    incidentsState.lastUpdated || 0,
  )

  const handleAcknowledge = async (id: number) => {
    setBusyIncidentId(id)
    setActionError(null)
    try {
      await api.acknowledgeIncident(id)
      incidentsState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to acknowledge incident')
    } finally {
      setBusyIncidentId(null)
    }
  }

  const handleResolve = async (id: number) => {
    setBusyIncidentId(id)
    setActionError(null)
    try {
      await api.resolveIncident(id)
      incidentsState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to resolve incident')
    } finally {
      setBusyIncidentId(null)
    }
  }

  const handleInvestigating = async (id: number) => {
    setBusyIncidentId(id)
    setActionError(null)
    try {
      await api.markInvestigating(id)
      incidentsState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to mark incident as investigating')
    } finally {
      setBusyIncidentId(null)
    }
  }

  const handleReopen = async (id: number) => {
    setBusyIncidentId(id)
    setActionError(null)
    try {
      await api.reopenIncident(id)
      incidentsState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to reopen incident')
    } finally {
      setBusyIncidentId(null)
    }
  }

  const handleSuppress = async (id: number) => {
    setBusyIncidentId(id)
    setActionError(null)
    try {
      await api.suppressIncident(id, 'Suppressed by dashboard operator')
      incidentsState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to suppress incident')
    } finally {
      setBusyIncidentId(null)
    }
  }

  const handleKnowledgeApprove = async (id: number) => {
    setKnowledgeBusyId(id)
    setActionError(null)
    try {
      await api.approveKnowledge(id)
      knowledgeState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to approve knowledge')
    } finally {
      setKnowledgeBusyId(null)
    }
  }

  const handleKnowledgeReject = async (id: number) => {
    setKnowledgeBusyId(id)
    setActionError(null)
    try {
      await api.rejectKnowledge(id)
      knowledgeState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to reject knowledge')
    } finally {
      setKnowledgeBusyId(null)
    }
  }

  const handleKnowledgeDeprecate = async (id: number) => {
    setKnowledgeBusyId(id)
    setActionError(null)
    try {
      await api.deprecateKnowledge(id)
      knowledgeState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to deprecate knowledge')
    } finally {
      setKnowledgeBusyId(null)
    }
  }

  const handleInvestigate = async (id: number) => {
    setManualBusy(true)
    setActionError(null)
    try {
      await api.investigate(id)
      selectedInvestigationState.refresh()
      investigationsState.refresh()
      queueState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to queue investigation')
    } finally {
      setManualBusy(false)
    }
  }

  const handleApproveFollowup = async (actionId: FollowupActionId) => {
    if (!selectedIncident || !displayedInvestigation) return
    setFollowupBusyId(actionId)
    setActionError(null)
    try {
      await api.approveInvestigationFollowup(selectedIncident.id, {
        source_investigation_id: displayedInvestigation.id,
        followup_action_id: actionId,
        approved_by: 'dashboard operator',
      })
      followupState.refresh()
      selectedInvestigationState.refresh()
      investigationsState.refresh()
      queueState.refresh()
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to collect approved evidence')
      followupState.refresh()
      selectedInvestigationState.refresh()
      investigationsState.refresh()
    } finally {
      setFollowupBusyId(null)
    }
  }

  const handleInvestigationFeedback = async (feedbackType: string, userCorrection?: string) => {
    if (!selectedIncident || !displayedInvestigation) return
    const result = displayedInvestigation.structured_json
    const retrievedKnowledgeIds = (result?.evidence_inventory || [])
      .filter((item) => item.source_type === 'knowledge')
      .map((item) => Number(item.payload?.knowledge_id))
      .filter((id) => Number.isFinite(id))
    try {
      await api.submitFeedback({
        incident_id: selectedIncident.id,
        investigation_id: displayedInvestigation.id,
        original_query: `Investigate incident ${selectedIncident.id}: ${selectedIncident.title}`,
        model_response: result || {},
        model_version: displayedInvestigation.model_name || 'qwen2.5:3b',
        prompt_version: 'evidence-grounded-v1',
        retrieved_knowledge_ids: retrievedKnowledgeIds,
        feedback_type: feedbackType,
        user_correction: userCorrection,
      })
      setActionError(null)
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Unable to submit investigation feedback')
    }
  }

  const navigateTo = (href: string) => {
    document.querySelector(href)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const serviceError = healthState.error || containersState.error || incidentsState.error

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Activity size={21} /></div>
          <div><strong>Ops<span>Monitor</span></strong><small>LOCAL NOC · V2</small></div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="side-nav">
          {navigation.map(({ label, href, icon: Icon }, index) => (
            <button key={href} className={index === 0 ? 'nav-item nav-item-active' : 'nav-item'} onClick={() => navigateTo(href)}>
              <Icon size={17} /><span>{label}</span>{label === 'Incident center' && activeIncidents.length > 0 && <b className="nav-count">{activeIncidents.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-service">
            <span className={`service-dot ${healthState.data?.docker.connected ? 'service-up' : 'service-down'}`} />
            <span>Docker Engine</span>
            <small>{healthState.data?.docker.connected ? 'Connected' : 'Unavailable'}</small>
          </div>
          <div className="sidebar-service">
            <span className={`service-dot ${healthState.data?.ollama.connected ? 'service-up' : 'service-down'}`} />
            <span>Ollama</span>
            <small>{healthState.data?.ollama.connected ? 'Connected' : 'Unavailable'}</small>
          </div>
          <p className="sidebar-footnote">Read-only monitoring<br />Remediation is never automatic</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb"><span>Operations</span><span className="breadcrumb-separator">/</span><strong>Overview</strong></div>
          <div className="topbar-right">
            <span className="local-badge"><span /> LOCAL ENVIRONMENT</span>
            <span className="topbar-divider" />
            <span className="topbar-clock">{lastRefresh ? `Updated ${formatDate(lastRefresh)}` : 'Connecting…'}</span>
            <button className="icon-button refresh-button" title="Refresh dashboard data" onClick={() => { healthState.refresh(); containersState.refresh(); monitorState.refresh(); incidentsState.refresh(); investigationsState.refresh(); queueState.refresh(); knowledgeState.refresh() }}><RefreshCw size={15} /></button>
          </div>
        </header>

        <div className="page-content">
          <section id="overview" className="hero-section">
            <div>
              <div className="hero-kicker"><span className="pulse-dot" /> LIVE MONITORING</div>
              <h1>Operations overview</h1>
              <p>Docker infrastructure health, incidents, and local AI investigation in one place.</p>
            </div>
            <div className="monitor-status">
              <span className={`monitor-indicator ${monitorState.data?.running ? 'monitor-active' : ''}`}><Activity size={15} /></span>
              <span><strong>{monitorState.data?.running ? 'Monitor active' : 'Monitor unavailable'}</strong><small>{monitorState.data ? `Polling every ${monitorState.data.poll_interval_seconds}s` : 'Waiting for monitor status'}</small></span>
            </div>
          </section>

          {serviceError && <div className="global-error"><AlertCircle size={16} /><span>Backend data is unavailable: {serviceError}. Last successful data remains visible where available.</span><button onClick={() => { containersState.refresh(); healthState.refresh(); incidentsState.refresh() }}>Retry</button></div>}
          {actionError && <div className="global-error"><AlertTriangle size={16} /><span>{actionError}</span><button onClick={() => setActionError(null)}>Dismiss</button></div>}

          <section className="summary-grid" aria-label="Infrastructure summary">
            <MetricCard label="Total containers" value={containersState.loading && !containersState.data ? '—' : containers.length} detail="Docker inventory" icon={ContainerIcon} tone="blue" />
            <MetricCard label="Running" value={runningContainers.length} detail="Active workloads" icon={CheckCircle2} tone="green" />
            <MetricCard label="Stopped" value={stoppedCount} detail="Not currently running" icon={Box} tone="amber" />
            <MetricCard label="Unhealthy" value={unhealthyCount} detail="Docker health checks" icon={AlertTriangle} tone="red" />
            <MetricCard label="Active incidents" value={activeIncidents.length} detail="Open or acknowledged" icon={ShieldAlert} tone="amber" />
            <MetricCard label="Critical" value={criticalIncidents.length} detail="Requires attention" icon={Zap} tone="red" />
          </section>

          <div className="content-grid telemetry-grid">
            <section id="infrastructure" className="grid-span-full">
              <SectionHeading eyebrow="INFRASTRUCTURE" title="Container fleet" description="Select a container to inspect live metrics. Data is read from the Docker Engine API." />
              <ContainerTable
                containers={containers}
                metrics={metricState.metrics}
                diagnostics={diagnosticsState.data || {}}
                selectedId={selectedContainerId}
                lastUpdated={metricState.lastUpdated}
                loading={containersState.loading}
                onSelect={setSelectedContainerId}
              />
            </section>
            <div className="grid-span-full">
              <ContainerDetails
                container={selectedContainer}
                diagnostics={selectedContainerId ? diagnosticsState.data?.[selectedContainerId] || null : null}
              />
            </div>
            <div className="grid-span-full">
              <MetricCharts
                metrics={selectedMetrics}
                history={selectedHistory}
                persistedHistory={persistedMetricHistoryState.data}
                containerName={selectedContainer?.name}
                loading={metricState.loading}
              />
            </div>
            <section id="incidents" className="grid-span-full">
              <SectionHeading eyebrow="INCIDENT RESPONSE" title="Incident center" description="Acknowledge and resolve alerts from the monitoring engine." />
              {incidentsState.error && <div className="inline-notice"><AlertCircle size={15} /> Incident API unavailable: {incidentsState.error}</div>}
              <IncidentCenter
                incidents={incidents}
                loading={incidentsState.loading}
                selectedId={selectedIncidentId}
                busyId={busyIncidentId}
                onSelect={(incident) => setSelectedIncidentId(incident.id)}
                onAcknowledge={handleAcknowledge}
                onResolve={handleResolve}
                onInvestigating={handleInvestigating}
                onReopen={handleReopen}
                onSuppress={handleSuppress}
              />
            </section>
            <section id="investigations" className="grid-span-full">
              <SectionHeading eyebrow="AI-ASSISTED RESPONSE" title="Investigation workspace" description="Evidence-based analysis from local Qwen. Investigations are advisory only." />
              <div className="content-grid investigation-grid">
                <InvestigationPanel
                  incident={selectedIncident}
                  investigation={displayedInvestigation}
                  loading={selectedInvestigationState.loading}
                  error={selectedInvestigationState.error}
                  busy={manualBusy}
                  onInvestigate={handleInvestigate}
                  onApproveFollowup={handleApproveFollowup}
                  followups={followupState.data || []}
                  followupBusyId={followupBusyId}
                  onFeedback={handleInvestigationFeedback}
                />
                <InvestigationHistory
                  investigations={investigations}
                  loading={investigationsState.loading}
                  selectedId={selectedIncidentId}
                  onSelect={(incidentId) => {
                    setSelectedIncidentId(incidentId)
                    window.setTimeout(() => navigateTo('#investigations'), 0)
                  }}
                />
              </div>
              {investigationsState.error && <div className="inline-notice"><AlertCircle size={15} /> Investigation history unavailable: {investigationsState.error}</div>}
              {queueState.error && <div className="inline-notice"><AlertCircle size={15} /> Investigation worker status unavailable: {queueState.error}</div>}
            </section>
              <section id="knowledge" className="grid-span-full">
                <SectionHeading eyebrow="PERSISTENT MEMORY" title="Knowledge Center" description="Approved operational knowledge can be retrieved by future investigations." />
                <KnowledgeCenter
                  records={knowledgeState.data || []}
                  loading={knowledgeState.loading}
                  busyId={knowledgeBusyId}
                  onApprove={handleKnowledgeApprove}
                  onReject={handleKnowledgeReject}
                  onDeprecate={handleKnowledgeDeprecate}
                />
              </section>
          </div>

          <footer className="page-footer">
            <span><HardDrive size={13} /> Data from local Docker Engine</span>
            <span><Network size={13} /> API <StatusBadge value={healthState.data?.api === 'ok' ? 'healthy' : 'unknown'} /></span>
            <span><Cpu size={13} /> {containers.length} containers observed · {monitorState.data?.containers_observed ?? 0} in last poll</span>
            <span className="footer-model"><BrainCircuit size={13} /> {healthState.data?.ollama.model || queueState.data?.model || 'Local AI'}</span>
          </footer>
        </div>
      </main>
      <div className="sr-only" aria-live="polite">{queueState.data?.queue_depth ? `${queueState.data.queue_depth} investigations waiting` : 'No investigations waiting'}</div>
    </div>
  )
}
