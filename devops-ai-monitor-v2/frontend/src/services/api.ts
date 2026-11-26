import type {
  Container,
  ContainerDiagnostics,
  ContainerMetrics,
  HealthResponse,
  Incident,
  Investigation,
  InvestigationStatus,
  MetricHistoryResponse,
  MonitorStatus,
  KnowledgeRecord,
  InvestigationFeedback,
  InvestigationFollowup,
  FollowupActionId,
} from '../types/api'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '')
const API_KEY = (import.meta.env.VITE_API_KEY || '').trim()

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
      ...init?.headers,
    },
  })

  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json() as { detail?: string }
      if (body.detail) message = body.detail
    } catch {
      // Use the HTTP status when the server does not return JSON.
    }
    throw new Error(message)
  }

  return response.json() as Promise<T>
}

export const api = {
  health: (signal?: AbortSignal) =>
    request<HealthResponse>('/health', { signal }),
  containers: (signal?: AbortSignal) =>
    request<Container[]>('/containers?all=true', { signal }),
  diagnostics: (containerId: string, signal?: AbortSignal) =>
    request<ContainerDiagnostics>(`/containers/${encodeURIComponent(containerId)}/diagnostics`, { signal }),
  metrics: (containerId: string, signal?: AbortSignal) =>
    request<ContainerMetrics>(`/containers/${encodeURIComponent(containerId)}/metrics`, { signal }),
  metricHistory: (containerId: string, minutes = 60, signal?: AbortSignal) =>
    request<MetricHistoryResponse>(
      `/containers/${encodeURIComponent(containerId)}/metric-history?minutes=${minutes}&limit=720`,
      { signal },
    ),
  monitorStatus: (signal?: AbortSignal) =>
    request<MonitorStatus>('/monitor/status', { signal }),
  incidents: (signal?: AbortSignal) =>
    request<Incident[]>('/incidents', { signal }),
  acknowledgeIncident: (id: number) =>
    request<Incident>(`/incidents/${id}/acknowledge`, { method: 'POST' }),
  resolveIncident: (id: number) =>
    request<Incident>(`/incidents/${id}/resolve`, { method: 'POST' }),
  markInvestigating: (id: number) =>
    request<Incident>(`/incidents/${id}/investigating`, { method: 'POST' }),
  reopenIncident: (id: number) =>
    request<Incident>(`/incidents/${id}/reopen`, { method: 'POST' }),
  suppressIncident: (id: number, comment: string) =>
    request<Incident>(`/incidents/${id}/suppress`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment, actor: 'dashboard operator' }),
    }),
  investigation: (id: number, signal?: AbortSignal) =>
    request<Investigation>(`/incidents/${id}/investigation`, { signal }),
  investigationFollowups: (id: number, signal?: AbortSignal) =>
    request<InvestigationFollowup[]>(`/incidents/${id}/investigation-followups`, { signal }),
  approveInvestigationFollowup: (
    id: number,
    approval: { source_investigation_id: number; followup_action_id: FollowupActionId; approved_by?: string },
  ) =>
    request<{ approved: boolean; followup: InvestigationFollowup; reassessment_queued: boolean; reassessment: Investigation }>(
      `/incidents/${id}/investigation-followups`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(approval),
      },
    ),
  investigate: (id: number) =>
    request<{ queued: boolean; investigation: Investigation }>(`/incidents/${id}/investigate`, { method: 'POST' }),
  investigations: (signal?: AbortSignal) =>
    request<Investigation[]>('/investigations?limit=100', { signal }),
  investigationStatus: (signal?: AbortSignal) =>
    request<InvestigationStatus>('/investigations/status', { signal }),
  knowledge: (signal?: AbortSignal) =>
    request<KnowledgeRecord[]>('/knowledge?limit=100', { signal }),
  knowledgeSearch: (query: string, signal?: AbortSignal) =>
    request<KnowledgeRecord[]>(`/knowledge/search?q=${encodeURIComponent(query)}&approved_only=false&limit=50`, { signal }),
  approveKnowledge: (id: number) =>
    request<KnowledgeRecord>(`/knowledge/${id}/approve`, { method: 'POST' }),
  rejectKnowledge: (id: number) =>
    request<KnowledgeRecord>(`/knowledge/${id}/reject`, { method: 'POST' }),
  deprecateKnowledge: (id: number) =>
    request<KnowledgeRecord>(`/knowledge/${id}/deprecate`, { method: 'POST' }),
  submitFeedback: (feedback: {
    incident_id: number
    investigation_id: number
    original_query: string
    model_response: Record<string, unknown>
    model_version: string
    prompt_version: string
    retrieved_knowledge_ids: number[]
    feedback_type: string
    user_correction?: string
  }) =>
    request<InvestigationFeedback>('/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(feedback),
    }),
}

export { API_BASE_URL }
