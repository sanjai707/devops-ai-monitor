import type {
  Container,
  ContainerDiagnostics,
  ContainerMetrics,
  HealthResponse,
  Incident,
  Investigation,
  InvestigationStatus,
  MonitorStatus,
} from '../types/api'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
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
  monitorStatus: (signal?: AbortSignal) =>
    request<MonitorStatus>('/monitor/status', { signal }),
  incidents: (signal?: AbortSignal) =>
    request<Incident[]>('/incidents', { signal }),
  acknowledgeIncident: (id: number) =>
    request<Incident>(`/incidents/${id}/acknowledge`, { method: 'POST' }),
  resolveIncident: (id: number) =>
    request<Incident>(`/incidents/${id}/resolve`, { method: 'POST' }),
  investigation: (id: number, signal?: AbortSignal) =>
    request<Investigation>(`/incidents/${id}/investigation`, { signal }),
  investigate: (id: number) =>
    request<{ queued: boolean; investigation: Investigation }>(`/incidents/${id}/investigate`, { method: 'POST' }),
  investigations: (signal?: AbortSignal) =>
    request<Investigation[]>('/investigations?limit=100', { signal }),
  investigationStatus: (signal?: AbortSignal) =>
    request<InvestigationStatus>('/investigations/status', { signal }),
}

export { API_BASE_URL }
