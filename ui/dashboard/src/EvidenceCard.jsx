import React from 'react'
import { Band, Status } from './Ledger.jsx'

// Everything the verdict rests on, in one panel. The test of this view is
// whether someone who disagrees with a band can point at the exact input they
// disagree with -- so nothing here is summarised away.

export default function EvidenceCard({ record, onClose }) {
  if (record.loading) {
    return (
      <div className="drawer">
        <p className="muted">Loading…</p>
      </div>
    )
  }
  if (record.error) {
    return (
      <div className="drawer">
        <p className="bad">{record.error}</p>
        <button className="ghost" onClick={onClose}>
          Close
        </button>
      </div>
    )
  }

  return (
    <div className="drawer">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
        <div>
          <h2>
            <Band value={record.band} />
          </h2>
          <p className="mono small muted" style={{ margin: '6px 0 0' }}>
            {record.record_id}
          </p>
        </div>
        <button className="ghost" onClick={onClose}>
          Close
        </button>
      </div>

      {record.reason && <p className="small">{record.reason}</p>}

      <section>
        <h3>The assumption this rests on</h3>
        <p className="small">{record.capture_sentence}</p>
      </section>

      <section>
        <h3>The verdict</h3>
        <dl className="kv">
          <dt>Ledger</dt>
          <dd>{record.ledger}</dd>
          <dt>Function</dt>
          <dd>
            {record.function} <Status value={record.function_status} />
          </dd>
          <dt>Algorithm</dt>
          <dd>
            {record.algorithm ?? '—'} <Status value={record.algorithm_status} />
          </dd>
          {record.windows.map((w, i) => (
            <React.Fragment key={i}>
              <dt>Exposed window</dt>
              <dd className="mono">
                {w.start} → {w.end} ({w.days} days)
              </dd>
            </React.Fragment>
          ))}
          {record.deadline && (
            <>
              <dt>Deadline (Z − X)</dt>
              <dd className="mono">{record.deadline}</dd>
            </>
          )}
          {record.conditional_band && (
            <>
              <dt>Would be</dt>
              <dd>
                <Band value={record.conditional_band} /> if the missing input
                went the worst way
              </dd>
            </>
          )}
          {record.M && (
            <>
              <dt>Clock stopped (M)</dt>
              <dd className="mono">{record.M}</dd>
            </>
          )}
          {record.X && (
            <>
              <dt>Secrecy lifetime X</dt>
              <dd>{record.X}</dd>
            </>
          )}
          {record.A && (
            <>
              <dt>Authenticity lifetime A</dt>
              <dd>{record.A}</dd>
            </>
          )}
        </dl>
      </section>

      <section>
        <h3>When did this start</h3>
        <dl className="kv">
          <dt>Could have, since</dt>
          <dd className="mono">{record.start_possible ?? 'nothing bounds it'}</dd>
          <dt>Proved, since</dt>
          <dd className="mono">{record.start_confirmed ?? 'nothing confirms it'}</dd>
        </dl>
        <div style={{ marginTop: 8 }}>
          {Object.entries(record.temporal_status).map(([field, state]) => (
            <div key={field} className="small">
              <span className="mono muted">{field}</span> <Status value={state} />
            </div>
          ))}
        </div>
      </section>

      {record.binding && (
        <section>
          <h3>Data class</h3>
          <dl className="kv">
            <dt>Classification</dt>
            <dd>{record.binding.classification}</dd>
            <dt>Status</dt>
            <dd>
              <Status value={record.binding.status} />
            </dd>
            <dt>Cited row</dt>
            <dd className="mono small">{record.binding.cited_table_row}</dd>
            <dt>Source</dt>
            <dd className="small">{record.binding.source_ref}</dd>
          </dl>
        </section>
      )}

      {record.migrations.length > 0 && (
        <section>
          <h3>Upgrade observations</h3>
          {record.migrations.map((m, i) => (
            <div className="card" key={i}>
              <div className="small">
                <span className="mono">{m.observed_at}</span> from{' '}
                <span className="mono">{m.vantage}</span> <Status value={m.status} />
              </div>
              <div className="small">
                negotiated {m.negotiated_group ?? '—'}; classical{' '}
                {m.classical_still_accepted ? 'still accepted' : 'refused'}
              </div>
              <div className={`small ${m.stops_the_clock ? 'ok' : 'muted'}`}>
                {m.stops_the_clock
                  ? 'stops the clock'
                  : 'does not stop the clock (not an observation, or classical still accepted)'}
              </div>
            </div>
          ))}
        </section>
      )}

      <section>
        <h3>Evidence used</h3>
        {record.evidence_refs.length === 0 ? (
          <p className="muted small">None — that is why this row is unbounded.</p>
        ) : (
          record.evidence_refs.map((ref, i) => (
            <div key={i} className="small">
              <span className="mono">{ref.id}</span> <Status value={ref.status} />
              {ref.ts && <span className="muted mono"> {ref.ts}</span>}
            </div>
          ))
        )}
      </section>

      {record.closure_tasks.length > 0 && (
        <section>
          <h3>To settle this</h3>
          {record.closure_tasks.map((task) => (
            <div className="card" key={task.key}>
              <h4>{task.collect}</h4>
              <p className="small">{task.method}</p>
              <p className="small muted">{task.bounds}</p>
            </div>
          ))}
        </section>
      )}

      <section>
        <h3>Policy in force</h3>
        <dl className="kv">
          <dt>Capture assumption</dt>
          <dd className="mono">{record.policy.capture_assumption}</dd>
          <dt>Accept inferred</dt>
          <dd>{String(record.policy.accept_inferred_inputs)}</dd>
          <dt>Accept declared go-live</dt>
          <dd>{String(record.policy.accept_declared_go_live)}</dd>
          <dt>Rollout Y</dt>
          <dd>{record.policy.rollout_Y}</dd>
        </dl>
      </section>

      <section>
        <h3>Show your working</h3>
        <dl className="kv">
          <dt>Rule</dt>
          <dd className="mono small">{record.provenance.rule_version}</dd>
          <dt>Calculation</dt>
          <dd className="mono small">v{record.provenance.calc_version}</dd>
          <dt>Input fingerprint</dt>
          <dd className="mono small">{record.provenance.inputs_sha256}</dd>
          <dt>Re-run now</dt>
          <dd className={record.replay.matches ? 'ok' : 'bad'}>
            {record.replay.matches
              ? `same answer (${record.replay.band})`
              : `DIFFERENT: ${record.replay.band}`}
            {record.replay.hash_stable ? ', same inputs' : ', inputs changed'}
          </dd>
        </dl>
      </section>
    </div>
  )
}
