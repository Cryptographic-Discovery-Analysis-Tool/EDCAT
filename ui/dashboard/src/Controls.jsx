import React from 'react'

// The assumptions panel. It is the first thing on screen, at full size, and
// not hidden behind a settings icon -- a tool whose answers depend on two
// chosen assumptions has to show them being chosen.

export default function Controls({ meta, policy, onChange, exportUrl, scenario }) {
  const set = (patch) => onChange({ ...policy, ...patch })

  return (
    <aside className="sidebar">
      <div className="brand">
        <h1>Pramāṇa</h1>
        <p>Exposure ledger</p>
      </div>

      <div className="field">
        <label htmlFor="scenario">When is Z?</label>
        <select
          id="scenario"
          value={policy.scenario}
          onChange={(e) => set({ scenario: e.target.value })}
        >
          {(meta?.scenarios ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.label} — {s.z_date}
            </option>
          ))}
        </select>
        {scenario && <p className="note">Basis: {scenario.basis_citation}</p>}
      </div>

      <div className="field">
        <label htmlFor="capture">Assume recording since</label>
        <select
          id="capture"
          value={policy.capture}
          onChange={(e) => set({ capture: e.target.value })}
        >
          <option value="SINCE_CONFIRMED">
            SINCE_CONFIRMED — when we can prove traffic flowed
          </option>
          <option value="SINCE_POSSIBLE">
            SINCE_POSSIBLE — the earliest it could have
          </option>
          <option value="SINCE_DATE">SINCE_DATE — a date you name</option>
        </select>
        {policy.capture === 'SINCE_DATE' && (
          <input
            type="date"
            value={policy.since}
            onChange={(e) => set({ since: e.target.value })}
          />
        )}
      </div>

      <div className="field">
        <label htmlFor="rollout">Rollout window Y (days)</label>
        <input
          id="rollout"
          type="number"
          min="0"
          value={policy.rollout_y_days}
          onChange={(e) => set({ rollout_y_days: Number(e.target.value) })}
        />
        <p className="note">
          {meta?.rollout_y_note ??
            'No cited default exists. Whatever you set is your assumption.'}
        </p>
      </div>

      <div className="field">
        <label htmlFor="asof">Evaluate as of</label>
        <input
          id="asof"
          type="date"
          value={policy.as_of}
          onChange={(e) => set({ as_of: e.target.value })}
        />
      </div>

      <div className="checkbox">
        <input
          id="inferred"
          type="checkbox"
          checked={policy.accept_inferred}
          onChange={(e) => set({ accept_inferred: e.target.checked })}
        />
        <label htmlFor="inferred" style={{ textTransform: 'none', letterSpacing: 0 }}>
          Accept inferred evidence as if observed
        </label>
      </div>
      <p className="note">
        Off by default. Turning this on lets a configuration file settle a row
        that nobody watched happen.
      </p>

      <a href={exportUrl} download="pramana-cbom.json">
        <button style={{ width: '100%' }}>Export CycloneDX 1.6</button>
      </a>
      <p className="small muted">
        One file, all three Z dates. Schema-validated and scanned for key
        material before it is written.
      </p>
    </aside>
  )
}
