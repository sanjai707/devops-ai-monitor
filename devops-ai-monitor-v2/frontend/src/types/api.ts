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

export type IncidentStatus =
  | 'open'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'reopened'
  | 'suppressed'
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
  first_seen_at?: string
  last_seen_at?: string
  event_count?: number
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

export type FollowupActionId = 'docker.container-events' | 'docker.container-logs'

export type InvestigationFollowup = {
  id: number
  incident_id: number
  source_investigation_id: number
  reassessment_investigation_id: number | null
  container_id: string
  action_id: FollowupActionId
  status: 'collecting' | 'collected' | 'unavailable' | 'failed' | string
  approved_by: string
  approved_at: string
  collected_at: string | null
  time_window: Record<string, string | number>
  request: Record<string, unknown>
  result: Record<string, unknown> | null
  limitations: string[]
  error_details: string | null
}

export type InvestigationRecommendation = {
  description: string
  followup_action_id?: FollowupActionId | null
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

export type PersistedMetricSample = {
  id: number
  container_id: string
  container_name: string
  observed_at: string
  cpu_percent: number | null
  memory_usage_bytes: number | null
  memory_limit_bytes: number | null
  memory_percent: number | null
  network_rx_bytes: number | null
  network_tx_bytes: number | null
  network_rx_rate_bytes_per_sec: number | null
  network_tx_rate_bytes_per_sec: number | null
  counter_reset: number
  running: number
  restart_count: number
  health_status: string | null
}

export type MetricHistoryResponse = {
  container_id: string
  window: { start: string; end: string; minutes: number }
  samples: PersistedMetricSample[]
  summary: {
    sample_count: number
    first_sample_at: string | null
    last_sample_at: string | null
    avg_cpu_percent: number | null
    max_cpu_percent: number | null
    avg_memory_percent: number | null
    max_memory_percent: number | null
    max_restart_count: number | null
    counter_resets: number
  }
}

export type KnowledgeRecord = {
  id: number
  title: string
  content: string
  category: string
  source: string
  incident_id: number | null
  verification_status: string
  approval_status: 'proposed' | 'pending_review' | 'approved' | 'rejected' | 'deprecated' | string
  confidence: string
  version: number
  tags: string[]
  created_at: string
  updated_at: string
}

export type InvestigationFeedback = {
  incident_id: number | null
  investigation_id: number | null
  original_query: string
  model_response: Record<string, unknown>
  model_version: string
  prompt_version: string
  retrieved_knowledge_ids: number[]
  feedback_type: string
  user_correction: string | null
  occurred_at: string
  review_status: string
  proposed_knowledge_id: number | null
}
