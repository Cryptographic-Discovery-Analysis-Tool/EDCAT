import React from 'react'
import { Band } from './Ledger.jsx'

// The queue is already ranked by the closure engine (§5.8: worst reachable
// band, rows affected, longest reachable window). Order is preserved as sent.

export default function Closure({ data }) {
  if (data.tasks.length === 0) {
    return <p className="muted">Nothing is waiting on evidence under this scenario.</p>
  }

  return (
    <>
      <p className="small muted" style={{ marginTop: 0 }}>
        Each task is the smallest thing that would settle the rows it names.
        Ranked by the worst answer it could reveal, then by how many rows it
        would settle.
      </p>

      {data.tasks.map((task, i) => (
        <div className="card" key={task.key}>
          <h4>
            {i + 1}. {task.collect}
          </h4>
          <p className="small">{task.method}</p>

          <dl className="kv">
            <dt>Why it settles them</dt>
            <dd className="small">{task.bounds}</dd>

            <dt>Rows it would settle</dt>
            <dd className="small mono">{task.rows.join(', ')}</dd>

            <dt>What you might find</dt>
            <dd>
              {task.reachable_bands.length === 0 ? (
                <span className="muted small">
                  Anything — this one narrows nothing until it is collected.
                </span>
              ) : (
                task.reachable_bands.map((b) => <Band key={b} value={b} />)
              )}
            </dd>

            {task.longest_reachable_window_days > 0 && (
              <>
                <dt>Longest window at stake</dt>
                <dd className="small">{task.longest_reachable_window_days} days</dd>
              </>
            )}

            <dt>Basis</dt>
            <dd className="small mono muted">{task.citation}</dd>
          </dl>
        </div>
      ))}
    </>
  )
}
