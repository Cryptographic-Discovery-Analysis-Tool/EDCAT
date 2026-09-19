import React, { useCallback, useEffect, useMemo, useState } from 'react'
import Controls from './Controls.jsx'
import Ledger from './Ledger.jsx'
import Closure from './Closure.jsx'
import Coverage from './Coverage.jsx'
import Recommend from './Recommend.jsx'
import EvidenceCard from './EvidenceCard.jsx'

// Presentation only. Every band, window and deadline shown here is computed by
// the ledger and arrives over the API already decided; nothing in this bundle
// thresholds, weights or re-derives anything. If a number appears on screen
// that was calculated in JavaScript, that is a bug.

const TABS = [
  ['ledger', 'Ledger'],
  ['closure', 'Closure queue'],
  ['recommend', 'Move to'],
  ['coverage', 'Coverage'],
]

export default function App() {
  const [meta, setMeta] = useState(null)
  const [policy, setPolicy] = useState({
    scenario: 'Z_central',
    capture: 'SINCE_CONFIRMED',
    since: '',
    accept_inferred: false,
    rollout_y_days: 365,
    as_of: '2026-09-18',
    profile: 'NIST_L3',
  })
  const [tab, setTab] = useState('ledger')
  const [data, setData] = useState({ ledger: null, closure: null, coverage: null })
  const [recommendations, setRecommendations] = useState(null)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const query = useMemo(() => {
    const q = new URLSearchParams({
      scenario: policy.scenario,
      capture: policy.capture,
      accept_inferred: String(policy.accept_inferred),
      rollout_y_days: String(policy.rollout_y_days),
    })
    if (policy.capture === 'SINCE_DATE' && policy.since) q.set('since', policy.since)
    if (policy.as_of) q.set('as_of', policy.as_of)
    return q.toString()
  }, [policy])

  useEffect(() => {
    Promise.all([
      fetch('api/scenarios').then((r) => r.json()),
      fetch('api/profiles').then((r) => r.json()),
    ])
      .then(([scenarios, profiles]) => setMeta({ ...scenarios, ...profiles }))
      .catch((e) => setError(String(e)))
  }, [])

  // Recommendations depend only on the profile: what to move to is a function
  // of what the key does, not of when Z is.
  useEffect(() => {
    fetch(`api/recommendations?profile=${policy.profile}`)
      .then((r) => r.json())
      .then(setRecommendations)
      .catch((e) => setError(String(e)))
  }, [policy.profile])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    Promise.all(
      ['ledger', 'closure', 'coverage'].map((name) =>
        fetch(`api/${name}?${query}`).then(async (r) => {
          if (!r.ok) throw new Error(`${name}: ${(await r.json()).detail ?? r.status}`)
          return r.json()
        })
      )
    )
      .then(([ledger, closure, coverage]) => {
        if (!cancelled) setData({ ledger, closure, coverage })
      })
      .catch((e) => !cancelled && setError(String(e.message ?? e)))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [query])

  const openRecord = useCallback(
    (recordId) => {
      setSelected({ loading: true })
      fetch(`api/records/${encodeURIComponent(recordId)}?${query}`)
        .then((r) => r.json())
        .then(setSelected)
        .catch((e) => setSelected({ error: String(e) }))
    },
    [query]
  )

  const exportUrl = useMemo(() => {
    const q = new URLSearchParams(query)
    q.delete('scenario')
    return `api/export?${q.toString()}`
  }, [query])

  const scenario = meta?.scenarios?.find((s) => s.id === policy.scenario)

  return (
    <div className="app">
      <Controls
        meta={meta}
        policy={policy}
        onChange={setPolicy}
        exportUrl={exportUrl}
        scenario={scenario}
      />

      <main className="main">
        <div className="banner">
          <strong>Fixture data.</strong> No sensor has run. These rows are
          constructed evidence used to exercise every band while the live
          connection prober is still being built &mdash; nothing here was
          observed on a real network.
        </div>

        <div className="tabs">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              className={tab === id ? 'active' : ''}
              onClick={() => setTab(id)}
            >
              {label}
              {id === 'closure' && data.closure ? ` (${data.closure.tasks.length})` : ''}
            </button>
          ))}
        </div>

        {error && <p className="bad">{error}</p>}
        {loading && <p className="muted">Recalculating…</p>}

        {tab === 'ledger' && data.ledger && (
          <Ledger data={data.ledger} onSelect={openRecord} />
        )}
        {tab === 'closure' && data.closure && <Closure data={data.closure} />}
        {tab === 'recommend' && recommendations && <Recommend data={recommendations} />}
        {tab === 'coverage' && data.coverage && <Coverage data={data.coverage} />}
      </main>

      {selected && <EvidenceCard record={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
