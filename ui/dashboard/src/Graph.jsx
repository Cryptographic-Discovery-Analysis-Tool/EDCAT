import React from 'react'

// P15: the evidence graph view. Presentation only -- every edge here is read
// off a real Relationship or a shares_public_key_unclaimed pair the API
// already carries. Claimed and unclaimed edges are rendered with visibly
// different weight (solid vs dashed, filled vs open marker) and neither ever
// collapses into the other. Named gaps are drawn as their own list, not as
// blank space, so a reader sees what this engine refuses to claim, not just
// what it does.

function Edge({ edge }) {
  const claimed = edge.strength === 'claimed'
  return (
    <div className={`graph-edge ${claimed ? 'claimed' : 'unclaimed'}`}>
      <div className="graph-edge-line">
        <span className="mono small">{edge.source}</span>
        <span className={`graph-edge-arrow ${claimed ? '' : 'weak'}`}>
          {claimed ? '──▶' : '┄┄▷'}
        </span>
        <span className="mono small">{edge.target}</span>
      </div>
      <div className="small faint">{edge.note}</div>
      <div className="small faint mono">
        {edge.type}
        {edge.rule_id ? ` · rule ${edge.rule_id}` : ' · no registered rule_id'}
        {edge.epistemic_state ? ` · ${edge.epistemic_state}` : ''}
      </div>
    </div>
  )
}

export default function Graph({ data }) {
  if (!data) return null
  const claimed = data.edges.filter((e) => e.strength === 'claimed')
  const unclaimed = data.edges.filter((e) => e.strength === 'unclaimed')

  return (
    <>
      {data.fixture && (
        <div className="banner">
          <strong>Fixture data.</strong> Three synthetic services, run through
          the real certificate adapter and the real correlation engine — not a
          scan of anything real.
        </div>
      )}

      <p className="small faint" style={{ marginTop: 0 }}>
        {data.nodes.length} asset(s). Every edge states its own type and basis;
        nothing is drawn without one.
      </p>

      <h4>Claimed — same-object ({claimed.length})</h4>
      {claimed.length === 0 ? (
        <p className="small faint">No certificate matched by DER hash in this view.</p>
      ) : (
        claimed.map((e, i) => <Edge key={`c-${i}`} edge={e} />)
      )}

      <h4 style={{ marginTop: 20 }}>Unclaimed — shares public key, not identity ({unclaimed.length})</h4>
      {unclaimed.length === 0 ? (
        <p className="small faint">No SPKI-only match in this view.</p>
      ) : (
        unclaimed.map((e, i) => <Edge key={`u-${i}`} edge={e} />)
      )}

      <h4 style={{ marginTop: 20 }}>Refused — named gaps, not blank space ({data.gaps.length})</h4>
      {data.gaps.map((g, i) => (
        <div className="graph-gap" key={i}>
          <div className="mono small">
            {g.from_layer} <span className="graph-edge-arrow gap">┄┄✕┄┄</span> {g.to_layer}
          </div>
          <div className="small faint">{g.why}</div>
        </div>
      ))}
    </>
  )
}
