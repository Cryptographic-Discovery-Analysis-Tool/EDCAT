import React from 'react'

// A glyph per band, so the distinction survives a colour-blind reader, a
// washed-out projector and a black-and-white printout. Bands are categories,
// not a severity ramp -- the tags are drawn at equal weight on purpose.
const GLYPH = {
  BLEEDING: '●',
  UNSAVABLE: '✕',
  UNBOUNDED: '?',
  SAVABLE: '◐',
  SAFE: '✓',
  SAFE_UNTIL_Z: '✓',
  ROTATE_BEFORE_Z: '↻',
  RESIGN_BEFORE_Z: '✎',
}

export const Band = ({ value }) => (
  <span className={`band band-${value}`}>
    <span className="glyph">{GLYPH[value] ?? '·'}</span>
    {value}
  </span>
)

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
            <th>Under other Z</th>
          </tr>
        </thead>
        <tbody>
          {data.rows.map((row) => (
            <tr key={row.record_id} onClick={() => onSelect(row.record_id)}>
              <td>
                <Band value={row.band} />
                {row.qualifiers.map((q) => (
                  <div key={q} className="small faint">
                    {q}
                  </div>
                ))}
                {row.conditional_band && (
                  <div className="small faint">could be {row.conditional_band}</div>
                )}
              </td>
              <td>
                <div className="small">{row.surface_id}</div>
                <div className="small faint">{row.asset_id}</div>
              </td>
              <td>
                <div className="small">
                  {row.function} <Status value={row.function_status} />
                </div>
                <div className="small faint">
                  {row.algorithm ?? 'algorithm unknown'}{' '}
                  {row.algorithm && <Status value={row.algorithm_status} />}
                </div>
              </td>
              <td>
                {row.windows.length === 0 ? (
                  <span className="faint small">
                    {row.band === 'UNBOUNDED' ? 'not derivable yet' : '—'}
                  </span>
                ) : (
                  row.windows.map((w, i) => (
                    <div key={i} className="small">
                      {w.start} → {w.end}
                      <span className="faint"> {w.days}d</span>
                    </div>
                  ))
                )}
              </td>
              <td className="small">{row.deadline ?? <span className="faint">—</span>}</td>
              <td className="small">
                {row.sensitivity?.scenario_sensitive ? (
                  <span
                    className="badge badge-sensitive"
                    title={row.sensitivity.under_scenario
                      .map((o) => `${o.label}: ${o.band}`)
                      .join(' · ')}
                  >
                    flips at {row.sensitivity.first_flip?.label ?? '?'}
                  </span>
                ) : (
                  <span className="faint">stable across Z</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <p className="small faint" style={{ marginTop: 16 }}>
        Ordered worst first by category, never by a score. Select a row for the
        evidence behind it.
      </p>
    </>
  )
}
