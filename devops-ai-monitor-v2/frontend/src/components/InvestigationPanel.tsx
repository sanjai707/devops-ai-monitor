import { AlertTriangle, BrainCircuit, ClipboardCheck, FileSearch, ListChecks, RotateCw, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import type {
  Incident,
  Investigation,
  InvestigationRecommendation,
  InvestigationFollowup,
  FollowupActionId,
} from '../types/api'
import { formatDate } from '../utils/format'
import { StatusBadge } from './StatusBadge'

type Props = {
  incident: Incident | null
  investigation: Investigation | null
  loading: boolean
  error: string | null
  busy: boolean
  followups: InvestigationFollowup[]
  followupBusyId: FollowupActionId | null
  onInvestigate: (id: number) => void
  onApproveFollowup: (actionId: FollowupActionId) => void
  onFeedback: (feedbackType: string, userCorrection?: string) => void
}

function StringList({ title, items, icon: Icon, tone = '' }: {
  title: string
  items: string[]
  icon: typeof FileSearch
  tone?: string
}) {
  if (!items.length) return null
  return (
    <div className="investigation-section">
      <h4 className={tone}><Icon size={14} /> {title}</h4>
      <ul>{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</ul>
    </div>
  )
}

export function InvestigationPanel({
  incident,
  investigation,
  loading,
  error,
  busy,
  followups,
  followupBusyId,
  onInvestigate,
  onApproveFollowup,
  onFeedback,
}: Props) {
  const result = investigation?.structured_json
  const [correction, setCorrection] = useState('')
  const evidenceById = new Map((result?.evidence_inventory || []).map((item) => [item.id, item]))

  function EvidenceRefs({ ids }: { ids: string[] }) {
    if (!ids.length) return <span className="muted-text">No validated evidence references</span>
    return (
      <div className="evidence-references">
        {ids.map((id) => {
          const item = evidenceById.get(id)
          return item ? (
            <details className="evidence-reference" key={id}>
              <summary>{id} · {item.source_type} · {item.status}</summary>
              <pre>{JSON.stringify(item.payload, null, 2)}</pre>
              {item.limitations.length > 0 && <small>{item.limitations.join(' ')}</small>}
            </details>
          ) : <span className="evidence-reference-missing" key={id}>{id} · unavailable</span>
        })}
      </div>
    )
  }

  function RecommendationList({ title, items, corrective = false }: {
    title: string
    items: InvestigationRecommendation[]
    corrective?: boolean
  }) {
    if (!items.length) return null
    return (
      <div className="investigation-section">
        <h4 className={corrective ? 'list-violet' : 'list-blue'}>{title}</h4>
        <div className="recommendation-list">
          {items.map((item, index) => (
            <article className="recommendation-card" key={`${title}-${index}`}>
              <strong>{item.description}</strong>
              <p>{item.reason}</p>
              <dl>
                <div><dt>Expected impact</dt><dd>{item.expected_impact}</dd></div>
                <div><dt>Risk</dt><dd>{item.risk_level}</dd></div>
                <div><dt>Approval</dt><dd>{item.required_approval ? 'Human approval required' : 'Read-only; no change'}</dd></div>
              </dl>
              {item.verification_steps.length > 0 && <p>Verify: {item.verification_steps.join('; ')}</p>}
              {corrective && <p>Rollback: {item.rollback_considerations}</p>}
              <EvidenceRefs ids={item.evidence_ids} />
              {!corrective && item.followup_action_id && (() => {
                const existing = followups.find((entry) =>
                  entry.source_investigation_id === investigation?.id
                  && entry.action_id === item.followup_action_id,
                )
                return (
                  <div className="followup-approval">
                    <p>Optional follow-up: collect only this container's {item.followup_action_id === 'docker.container-events' ? 'Docker lifecycle events' : 'timestamped stdout/stderr logs'} in the incident time window (maximum 15 minutes), then reassess with the new evidence.</p>
                    {existing ? (
                      <small>
                        Collection {existing.status}
                        {existing.reassessment_investigation_id
                          ? ` · reassessment #${existing.reassessment_investigation_id}`
                          : ''}
                      </small>
                    ) : (
                      <button
                        className="button-secondary"
                        disabled={followupBusyId !== null || busy || !incident || !investigation}
                        onClick={() => onApproveFollowup(item.followup_action_id as FollowupActionId)}
                      >
                        {followupBusyId === item.followup_action_id ? 'Collecting evidence…' : 'Approve collection & reassess'}
                      </button>
                    )}
                  </div>
                )
              })()}
            </article>
          ))}
        </div>
      </div>
    )
  }

  return (
    <section className="panel investigation-panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">LOCAL AI · OLLAMA</p>
          <h2><BrainCircuit size={19} /> Investigation</h2>
          <p className="section-description">{incident ? `Incident #${incident.id} · ${incident.container_name}` : 'Select an incident to inspect its investigation.'}</p>
        </div>
        {incident && <button className="button-secondary" disabled={busy || investigation?.status === 'pending' || investigation?.status === 'processing'} onClick={() => onInvestigate(incident.id)}><RotateCw size={14} className={busy ? 'spin' : ''} /> Investigate</button>}
      </div>

      {!incident ? (
        <div className="empty-state panel-empty"><FileSearch size={21} /><span>Select an incident from the incident center.</span></div>
      ) : loading && !investigation ? (
        <div className="empty-state panel-empty"><span className="loader" /> Loading investigation…</div>
      ) : error && !investigation ? (
        <div className="inline-notice"><AlertTriangle size={15} /> {error}</div>
      ) : !investigation ? (
        <div className="empty-state panel-empty"><FileSearch size={21} /><span>No investigation exists yet. Start one when ready.</span></div>
      ) : (
        <>
          <div className="investigation-meta">
            <StatusBadge value={investigation.status} />
            {investigation.confidence && <span className={`confidence confidence-${investigation.confidence}`}>{investigation.confidence} confidence</span>}
            <span className="meta-spacer" />
            <span>{investigation.model_name || 'Model pending'}</span>
            <span>{formatDate(investigation.investigated_at || investigation.updated_at)}</span>
          </div>

          {investigation.status === 'failed' && <div className="inline-notice notice-error"><AlertTriangle size={15} /><span><b>Investigation failed.</b> {investigation.error_details || 'The worker could not complete this investigation.'}</span></div>}
          {(investigation.status === 'pending' || investigation.status === 'processing') && <div className="inline-notice notice-info"><span className="loader" /> Investigation is {investigation.status}; this panel refreshes automatically.</div>}

          {result && (
            <div className="investigation-result">
              <div className="summary-box">
                <div className="summary-heading"><BrainCircuit size={15} /><span>AI incident summary</span></div>
                <p>{result.summary}</p>
              </div>

              <div className="root-cause-box">
                <div className="summary-heading"><FileSearch size={15} /><span>Probable cause · not confirmed</span></div>
                <p>{result.root_cause}</p>
              </div>
              {result.confidence_explanation && <p className="confidence-explanation">{result.confidence_explanation}</p>}
              {result.what_happened && <div className="investigation-section"><h4>What happened</h4><p>{result.what_happened}</p></div>}
              {result.what_changed && <div className="investigation-section"><h4>Observed changes</h4><p>{result.what_changed}</p></div>}

              {(result.findings || []).length > 0 && (
                <div className="investigation-section">
                  <h4>Evidence-linked findings</h4>
                  <div className="finding-list">
                    {result.findings!.map((finding, index) => (
                      <article className={`finding-card finding-${finding.classification}`} key={`${finding.classification}-${index}`}>
                        <div><span className="finding-label">{finding.classification.replaceAll('_', ' ')}</span><p>{finding.claim}</p></div>
                        <div><small>Supporting evidence</small><EvidenceRefs ids={finding.supporting_evidence_ids} /></div>
                        {finding.contradictory_evidence_ids.length > 0 && <div><small>Contradictory evidence</small><EvidenceRefs ids={finding.contradictory_evidence_ids} /></div>}
                      </article>
                    ))}
                  </div>
                </div>
              )}

              {(result.findings || []).length === 0 && <>
                <StringList title="Confirmed facts" items={result.confirmed_facts || []} icon={ClipboardCheck} tone="list-green" />
                <StringList title="Hypotheses" items={result.hypotheses || []} icon={BrainCircuit} tone="list-amber" />
                <StringList title="Supporting evidence" items={result.evidence || []} icon={FileSearch} />
              </>}
              <StringList title="Contradictory evidence" items={(result.contradictory_evidence || []).map((item) => `${item.claim} [${item.evidence_ids.join(', ')}]`)} icon={AlertTriangle} tone="list-amber" />
              <StringList title="Missing information" items={result.missing_information || []} icon={AlertTriangle} tone="list-amber" />
              <RecommendationList title="Recommended read-only checks" items={result.read_only_checks || []} />
              <RecommendationList title="Corrective actions · advisory only" items={result.corrective_actions || []} corrective />
              {(result.read_only_checks || []).length === 0 && <StringList title="Recommended read-only checks" items={result.recommended_checks || []} icon={ListChecks} tone="list-blue" />}
              {(result.corrective_actions || []).length === 0 && <StringList title="Suggested remediation · advisory only" items={result.suggested_remediation || []} icon={ShieldCheck} tone="list-violet" />}
              {(result.timeline || []).length > 0 && (
                <div className="investigation-section">
                  <h4>Incident timeline · correlation is not causation</h4>
                  <ol className="investigation-timeline">
                    {result.timeline!.map((item, index) => (
                      <li key={`${item.evidence_id}-${index}`}><time>{formatDate(item.timestamp)} · {item.relation_to_incident || 'unknown'}</time><span>{item.description}</span><EvidenceRefs ids={[item.evidence_id]} /></li>
                    ))}
                  </ol>
                </div>
              )}
              {(result.evidence_inventory || []).length > 0 && (
                <details className="evidence-inventory">
                  <summary>Collected evidence inventory ({result.evidence_inventory!.length})</summary>
                  <div>{result.evidence_inventory!.map((item) => <details className="evidence-inventory-item" key={item.id}><summary>{item.id} · {item.source_type} · {item.status} · {formatDate(item.event_timestamp)}</summary><pre>{JSON.stringify(item.payload, null, 2)}</pre><small>Collected {formatDate(item.collection_timestamp)} · {item.reliability}{item.limitations.length ? ` · ${item.limitations.join(' ')}` : ''}</small></details>)}</div>
                </details>
              )}
              <div className="investigation-feedback">
                <h4>Investigation feedback</h4>
                <div className="feedback-actions">
                  <button onClick={() => onFeedback('helpful')}>Helpful</button>
                  <button onClick={() => onFeedback('not_helpful')}>Not helpful</button>
                  <button onClick={() => onFeedback('correct')}>Correct</button>
                  <button onClick={() => onFeedback('incorrect')}>Incorrect</button>
                  <button onClick={() => onFeedback('root_cause_confirmed')}>Root cause confirmed</button>
                  <button onClick={() => onFeedback('root_cause_rejected')}>Root cause rejected</button>
                </div>
                <textarea
                  value={correction}
                  onChange={(event) => setCorrection(event.target.value)}
                  placeholder="Optional correction. Corrections require human review before knowledge is approved."
                  rows={3}
                />
                <button
                  className="button-secondary"
                  disabled={!correction.trim()}
                  onClick={() => {
                    onFeedback('user_correction', correction.trim())
                    setCorrection('')
                  }}
                >
                  Submit correction
                </button>
              </div>
              <div className="approval-note"><ShieldCheck size={15} /><span>Suggestions are advisory only. Human approval is always required; nothing is executed from this dashboard.</span></div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
