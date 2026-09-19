import React from 'react'
import { Band, Status } from './Ledger.jsx'

export default function Coverage({ data }) {
  return (
    <>
      <div className="counts">
        <div className="count">
          <span className="n">{data.rows}</span>
          <span className="muted">rows</span>
        </div>
        {Object.entries(data.by_function_status).map(([status, n]) => (
          <div className="count" key={status}>
            <span className="n">{n}</span>
            <Status value={status} />
          </div>
        ))}
      </div>

      <div className="card">
        <h4>What each sensor looked at</h4>
        <p className="small">{data.adapter_visibility.note}</p>
      </div>

      <section>
        <h3 style={{ color: 'var(--muted)', fontSize: 12, letterSpacing: '.06em' }}>
          SURFACES REACHING THE LEDGER
        </h3>
        <table>
          <thead>
            <tr>
              <th>Surface</th>
              <th>How we know what it is doing</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(data.surfaces).map(([surface, states]) => (
              <tr key={surface} style={{ cursor: 'default' }}>
                <td className="mono small">{surface}</td>
                <td>
                  {states.map((s) => (
                    <Status key={s} value={s} />
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {data.grover_flags.length > 0 && (
        <section style={{ marginTop: 24 }}>
          <h3 style={{ color: 'var(--muted)', fontSize: 12, letterSpacing: '.06em' }}>
            REPORTED BUT NOT BANDED
          </h3>
          {data.grover_flags.map((flag) => (
            <div className="card" key={flag.usage_context_id}>
              <h4 className="mono">{flag.algorithm ?? flag.usage_context_id}</h4>
              <p className="small mono muted">{flag.surface_id}</p>
              <p className="small">{flag.note}</p>
            </div>
          ))}
        </section>
      )}

      {data.skipped.length > 0 && (
        <section style={{ marginTop: 24 }}>
          <h3 style={{ color: 'var(--muted)', fontSize: 12, letterSpacing: '.06em' }}>
            SKIPPED
          </h3>
          {data.skipped.map((line) => (
            <p key={line} className="small mono">
              {line}
            </p>
          ))}
        </section>
      )}
    </>
  )
}
