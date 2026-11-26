import { expect, test } from '@playwright/test'

test('dashboard incident actions and approved evidence follow-up use the browser API flow', async ({ page }) => {
  const calls: Array<{ method: string; path: string; body?: unknown }> = []
  let incident: Record<string, unknown> = {
    id: 1,
    fingerprint: 'browser-test',
    container_id: 'container-full-id',
    container_name: 'browser-fixture',
    type: 'container_stopped',
    severity: 'warning',
    title: 'Browser test container stopped',
    status: 'open',
    evidence: { exit_code: 137, oom_killed: false },
    created_at: '2026-11-26T10:00:00Z',
    updated_at: '2026-11-26T10:00:00Z',
    acknowledged_at: null,
    resolved_at: null,
  }
  let followups: Array<Record<string, unknown>> = []
  const investigation = {
    id: 10,
    incident_id: 1,
    status: 'completed',
    summary: 'Exit code observed; source remains unknown.',
    root_cause: 'Insufficient evidence to determine the root cause.',
    confidence: 'low',
    structured_json: {
      summary: 'Exit code observed; source remains unknown.',
      root_cause: 'Insufficient evidence to determine the root cause.',
      confidence: 'low',
      confirmed_facts: [],
      hypotheses: ['Exit code 137 is consistent with SIGKILL.'],
      evidence: ['Container inspection observed exit code 137 [INS-001].'],
      missing_information: ['No retained Docker daemon events were available.'],
      recommended_checks: ['Review Docker events around termination.'],
      suggested_remediation: [],
      requires_human_approval: true,
      what_happened: 'The container stopped.',
      what_changed: 'A stopped state was observed.',
      confidence_explanation: 'Evidence is incomplete.',
      findings: [{
        claim: 'The container was inspected after exit.',
        classification: 'confirmed_fact',
        supporting_evidence_ids: ['INS-001'],
        contradictory_evidence_ids: [],
      }],
      contradictory_evidence: [],
      read_only_checks: [{
        description: 'Review Docker lifecycle events.',
        followup_action_id: 'docker.container-events',
        reason: 'Events may add context around termination.',
        evidence_ids: ['INS-001'],
        expected_impact: 'May add timestamped lifecycle context.',
        risk_level: 'low',
        required_approval: false,
        verification_steps: ['Compare event timestamps with incident time.'],
        rollback_considerations: 'Not applicable; read-only.',
      }],
      corrective_actions: [],
      evidence_inventory: [{
        id: 'INS-001',
        source_type: 'inspection',
        container_id: 'container-full-id',
        event_timestamp: '2026-11-26T10:00:00Z',
        collection_timestamp: '2026-11-26T10:00:01Z',
        payload: { status: 'exited', exit_code: 137, oom_killed: false },
        status: 'collected',
        reliability: 'docker_inspect_snapshot',
        limitations: [],
      }],
      timeline: [],
    },
    model_name: 'qwen2.5:3b',
    investigated_at: '2026-11-26T10:01:00Z',
    error_details: null,
    attempts: 1,
    created_at: '2026-11-26T10:00:00Z',
    updated_at: '2026-11-26T10:01:00Z',
  }
  let currentInvestigation: Record<string, unknown> = investigation

  await page.route('**/api/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace(/^\/api/, '')
    const method = request.method()
    let body: unknown
    try {
      body = request.postDataJSON()
    } catch {
      body = undefined
    }
    calls.push({ method, path, body })

    const json = async (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify(data),
      })

    if (path === '/health') {
      return json({
        api: 'ok',
        docker: { connected: true, error: null },
        ollama: { connected: true, url: 'http://ollama', model: 'qwen2.5:3b' },
      })
    }
    if (path === '/containers' || path.startsWith('/containers?')) return json([])
    if (path === '/monitor/status') {
      return json({ running: true, poll_interval_seconds: 10, poll_count: 5, last_poll_at: null, last_error: null, containers_observed: 0 })
    }
    if (path === '/incidents' && method === 'GET') return json([incident])
    if (path === '/incidents/1/acknowledge' && method === 'POST') {
      incident = { ...incident, status: 'acknowledged', acknowledged_at: '2026-11-26T10:02:00Z' }
      return json(incident)
    }
    if (path === '/incidents/1/investigation') return json(currentInvestigation)
    if (path === '/incidents/1/investigation-followups' && method === 'GET') return json(followups)
    if (path === '/incidents/1/investigation-followups' && method === 'POST') {
      const approval = body as { source_investigation_id: number; followup_action_id: string }
      followups = [{
        id: 20,
        incident_id: 1,
        source_investigation_id: approval.source_investigation_id,
        reassessment_investigation_id: 11,
        container_id: 'container-full-id',
        action_id: approval.followup_action_id,
        status: 'collected',
        approved_by: 'dashboard operator',
        approved_at: '2026-11-26T10:03:00Z',
        collected_at: '2026-11-26T10:03:01Z',
        time_window: { start: '2026-11-26T09:50:00Z', end: '2026-11-26T10:05:00Z' },
        request: { description: 'Review Docker lifecycle events.', evidence_ids: ['INS-001'] },
        result: { item_count: 1 },
        limitations: [],
        error_details: null,
      }]
      currentInvestigation = {
        id: 11,
        incident_id: 1,
        status: 'pending',
        summary: null,
        root_cause: null,
        confidence: null,
        structured_json: null,
        model_name: 'qwen2.5:3b',
        investigated_at: null,
        error_details: null,
        attempts: 0,
        created_at: '2026-11-26T10:03:01Z',
        updated_at: '2026-11-26T10:03:01Z',
      }
      return json({
        approved: true,
        followup: followups[0],
        reassessment_queued: true,
        reassessment: currentInvestigation,
      })
    }
    if (path === '/investigations') return json([currentInvestigation])
    if (path === '/investigations/status') {
      return json({ running: true, queue_depth: 0, investigations: { pending: 0, processing: 0, completed: 1, failed: 0 }, model: 'qwen2.5:3b' })
    }
    if (path === '/knowledge' || path.startsWith('/knowledge?')) return json([])
    if (path.includes('/metric-history')) return json({ container_id: 'none', window: { start: '', end: '', minutes: 60 }, samples: [], summary: { sample_count: 0 } })
    if (path.endsWith('/metrics')) return json({ id: 'none', name: 'none', cpu_percent: 0, memory_usage_bytes: 0, memory_limit_bytes: 0, memory_percent: 0, network_rx_bytes: 0, network_tx_bytes: 0, network_interfaces: [] })
    if (path.endsWith('/diagnostics')) return json({})
    return json({ detail: 'Unmocked browser-test endpoint' }, 404)
  })

  const pageErrors: string[] = []
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Incident center', exact: true }).first()).toBeVisible()

  await page.getByRole('button', { name: 'Ack' }).click()
  await expect(page.getByText('Acknowledged', { exact: true }).first()).toBeVisible()
  expect(calls.some((call) => call.method === 'POST' && call.path === '/incidents/1/acknowledge')).toBeTruthy()

  await page.getByRole('button', { name: 'Approve collection & reassess' }).click()
  await expect(page.getByRole('heading', { name: 'Approved evidence follow-ups' })).toBeVisible()
  await expect(page.getByText('Review Docker lifecycle events.')).toBeVisible()
  await expect(page.getByText('Reassessment investigation #11')).toBeVisible()
  await expect(page.getByText(/Investigation is pending/)).toBeVisible()
  const approval = calls.find((call) => call.method === 'POST' && call.path === '/incidents/1/investigation-followups')
  expect(approval?.body).toMatchObject({
    source_investigation_id: 10,
    followup_action_id: 'docker.container-events',
    approved_by: 'dashboard operator',
  })
  expect(pageErrors).toEqual([])
})
