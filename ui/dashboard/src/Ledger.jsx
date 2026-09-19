import React from 'react'

export const Band = ({ value }) => <span className={`band band-${value}`}>{value}</span>

export const Status = ({ value }) => (
  <span className={`status status-${value}`}>{value}</span>
)

// Rows arrive already ordered by the ledger (§5.10: band, then criticality,
// then longest window). This component does not sort them -- re-sorting here
// would silently replace the ranking the ledger is accountable for.

export default function Ledger({ data, onSelect }) {
  return (
    <>
      <div className="counts">
        {Object.entries(data.counts).map(([band, n]) => (
          <div className="count" key={band}>
            <span className="n">{n}</span>
            <Band value={band} />
          </div>
        ))}
      </div>

      <table>
        <thead>
          <tr>
            <th>Verdict</th>
            <th>Where</th>
            <th>Doing what</th>
            <th>Exposed window</th>
            <th>Deadline</th>
          </tr>
        </thead>
        <tbody>
          {data.rows.map((row) => (
            <tr key={row.record_id} onClick={() => onSelect(row.record_id)}>
              <td>
                <Band value={row.band} />
                {row.qualifiers.map((q) => (
                  <div key={q} className="small muted">
                    {q}
                  </div>
                ))}
                {row.conditional_band && (
                  <div className="small muted">could be {row.conditional_band}</div>
                )}
              </td>
              <td>
                <div className="mono small">{row.surface_id}</div>
                <div className="small muted">{row.asset_id}</div>
              </td>
              <td>
                <div>
                  {row.function} <Status value={row.function_status} />
                </div>
                <div className="small muted">
                  {row.algorithm ?? 'algorithm unknown'}{' '}
                  {row.algorithm && <Status value={row.algorithm_status} />}
                </div>
              </td>
              <td>
                {row.windows.length === 0 ? (
                  <span className="muted small">
                    {row.band === 'UNBOUNDED' ? 'not derivable yet' : 'none'}
                  </span>
                ) : (
                  row.windows.map((w, i) => (
                    <div key={i} className="small mono">
                      {w.start} → {w.end}
                      <span className="muted"> ({w.days} d)</span>
                    </div>
                  ))
                )}
              </td>
              <td className="mono small">{row.deadline ?? <span className="muted">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <p className="small muted" style={{ marginTop: 14 }}>
        Ordered worst first by category, never by a score. Click a row for the
        evidence behind it.
      </p>
    </>
  )
}
