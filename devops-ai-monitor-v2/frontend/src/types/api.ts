export type ServiceState = {
  connected: boolean
  error?: string | null
  url?: string
  model?: string
}

export type HealthResponse = {
  api: string
  docker: ServiceState
  ollama: ServiceState
}

export type Container = {
  id: string
  name: string
  image: string
  status: string
}

export type ContainerDiagnostics = {
  id: string
  name: string
  image: string
  status: string
  running: boolean
  paused: boolean
  restarting: boolean
  health_status: string | null
  health_failing_streak: number
  exit_code: number | null
  oom_killed: boolean
  restart_count: number
  restart_policy: string | null
  started_at: string | null
  finished_at: string | null
  error: string | null
}

export type ContainerMetrics = {
  id: string
  name: string
  cpu_percent: number
  memory_usage_bytes: number
  memory_limit_bytes: number
  memory_percent: number
  network_rx_bytes: number
  network_tx_bytes: number
  network_interfaces: string[]
}

export type MonitorStatus = {
  running: boolean
  poll_interval_seconds: number
  poll_count: number
  last_poll_at: string | null
  last_error: string | null
  containers_observed: number
}

export type IncidentStatus = 'open' | 'acknowledged' | 'resolved'
export type Severity = 'critical' | 'warning' | 'info' | string

export type Incident = {
  id: number
  fingerprint: string
  container_id: string
  container_name: string
  type: string
  severity: Severity
  title: string
  status: IncidentStatus
  evidence: Record<string, unknown>
  created_at: string
  updated_at: string
  acknowledged_at: string | null
  resolved_at: string | null
}

export type InvestigationResult = {
  summary: string
  root_cause: string
  confidence: 'low' | 'medium' | 'high' | string
  confirmed_facts: string[]
  hypotheses: string[]
  evidence: string[]
  missing_information: string[]
  recommended_checks: string[]
  suggested_remediation: string[]
  requires_human_approval: boolean
  what_happened?: string
  what_changed?: string
  confidence_explanation?: string
  findings?: InvestigationFinding[]
  contradictory_evidence?: Array<{ claim: string; evidence_ids: string[] }>
  evidence_inventory?: InvestigationEvidence[]
  timeline?: Array<{
    timestamp: string
    evidence_id: string
    source_type: string
    description: string
    relation_to_incident?: 'before' | 'at' | 'after' | 'unknown' | string
  }>
  read_only_checks?: InvestigationRecommendation[]
  corrective_actions?: InvestigationRecommendation[]
}

export type InvestigationFinding = {
  claim: string
  classification: 'confirmed_fact' | 'probable_explanation' | 'hypothesis' | 'unknown' | string
  supporting_evidence_ids: string[]
  contradictory_evidence_ids: string[]
}

export type InvestigationEvidence = {
  id: string
  source_type: string
  container_id: string | null
  event_timestamp: string | null
  collection_timestamp: string
  payload: Record<string, unknown>
  status: 'collected' | 'unavailable' | 'failed' | 'incomplete' | string
  reliability: string
  limitations: string[]
}

export type InvestigationRecommendation = {
  description: string
  reason: string
  evidence_ids: string[]
  expected_impact: string
  risk_level: 'low' | 'medium' | 'high' | 'unknown' | string
  required_approval: boolean
  verification_steps: string[]
  rollback_considerations: string
}

export type Investigation = {
  id: number
  incident_id: number
  status: 'pending' | 'processing' | 'completed' | 'failed' | string
  summary: string | null
  root_cause: string | null
  confidence: string | null
  structured_json: InvestigationResult | null
  model_name: string | null
  investigated_at: string | null
  error_details: string | null
  attempts: number
  created_at: string
  updated_at: string
}

export type InvestigationStatus = {
  running: boolean
  processing_investigation_id: number | null
  processing_incident_id: number | null
  last_error: string | null
  last_completed_at: string | null
  queue_depth: number
  investigations: Record<string, number>
  model: string
}

export type MetricPoint = {
  timestamp: number
  metrics: ContainerMetrics | null
}
