import React from 'react'

// Part 8. Keyed on purpose, so this view has no Z date and no scenario
// control: what to move to does not depend on when Z is, only on what the key
// is doing. That independence is the point of the view, not an oversight.

function Bytes({ cost }) {
  if (!cost) return <span className="faint">—</span>
  const parts = []
  if (cost.public_key_bytes) parts.push(`key ${cost.public_key_bytes} B`)
  if (cost.ciphertext_bytes) parts.push(`ciphertext ${cost.ciphertext_bytes} B`)
  if (cost.signature_bytes) parts.push(`signature ${cost.signature_bytes} B`)
  if (cost.signature_bytes_low)
    parts.push(
      `signature ${cost.signature_bytes_low}–${cost.signature_bytes_high} B`
    )
  if (cost.client_key_share_bytes)
    parts.push(
      `key share ${cost.client_key_share_bytes} B vs ${cost.baseline_key_share_bytes} B`
    )
  if (parts.length === 0) return <span className="faint">not in the cost table</span>
  return (
    <>
      {parts.join(' · ')}
      {cost.approximate && <span className="faint"> (approx, as sourced)</span>}
    </>
  )
}

export default function Recommend({ data }) {
  const determined = data.recommendations.filter((r) => !r.insufficient_evidence)
  const undetermined = data.recommendations.filter((r) => r.insufficient_evidence)

  return (
    <>
      <p className="small faint" style={{ marginTop: 0 }}>
        Keyed on what the key is <em>doing</em>, never on its algorithm name.
        The same RSA key gets a different answer depending on the job — and no
        answer at all when the job is undetermined.
      </p>

      <div className="counts">
        <div className="count">
          <span className="n">{determined.length}</span>
          <span className="muted small">with an option set</span>
        </div>
        <div className="count">
          <span className="n">{undetermined.length}</span>
          <span className="muted small">undetermined</span>
        </div>
        <div className="count">
          <span className="muted small">profile</span>
          <span className="small">{data.profile.label}</span>
        </div>
      </div>

      {data.hybrid_rationale?.quote && (
        <div className="card">
          <h4>Why hybrid on one clock and not the other</h4>
          <p className="small muted">{data.hybrid_rationale.quote}</p>
          <p className="small faint">{data.hybrid_rationale.citation}</p>
        </div>
      )}

      {determined.map((rec) => (
        <div className={`card ${rec.options.length ? 'accent' : ''}`} key={rec.usage_context_id}>
          <h4>
            {rec.usage_context_id}{' '}
            <span className="faint small">{rec.function}</span>
          </h4>
          <p className="small faint">
            currently {rec.current_algorithm ?? 'unknown algorithm'} on {rec.surface_id}
          </p>

          {rec.options.length === 0 ? (
            <p className="small muted">{rec.reason}</p>
          ) : (
            <>
              <table style={{ marginTop: 6 }}>
                <thead>
                  <tr>
                    <th>Move to</th>
                    <th>Standard</th>
                    <th>Cost</th>
                  </tr>
                </thead>
                <tbody>
                  {rec.options.map((o) => (
                    <tr key={o.algorithm} style={{ cursor: 'default' }}>
                      <td className="small">
                        {o.algorithm}
                        {o.parameter_set && (
                          <span className="faint"> / {o.parameter_set}</span>
                        )}
                        {o.hybrid && <span className="muted"> · hybrid</span>}
                      </td>
                      <td className="small faint">{o.standard}</td>
                      <td className="small">
                        <Bytes cost={o.cost} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {rec.options
                .filter((o) => o.caveat || o.note)
                .map((o) => (
                  <p className="note small" key={`n-${o.algorithm}`}>
                    <strong>{o.algorithm}:</strong> {o.caveat ?? o.note}
                  </p>
                ))}

              <p className="small faint" style={{ marginTop: 10 }}>
                {rec.reason}
              </p>
            </>
          )}
        </div>
      ))}

      {undetermined.length > 0 && (
        <section>
          <h3>Routed to coverage — no recommendation made</h3>
          {undetermined.map((rec) => (
            <div className="card" key={rec.usage_context_id}>
              <h4>{rec.usage_context_id}</h4>
              <p className="small muted">{rec.reason}</p>
            </div>
          ))}
        </section>
      )}
    </>
  )
}
