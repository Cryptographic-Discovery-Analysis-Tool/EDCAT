## ECDAT — Mandatory Architecture Corrections After Industrial Stress Test

The architecture is directionally strong, but it currently overstates what static multi-surface scanning can prove. Revise the design around the following principles.

### 1. Replace “complete discovery” with evidence-backed discovery

ECDAT must distinguish:

- crypto present
- crypto capable
- crypto referenced
- crypto observed
- crypto actually mapped to a security function

Never treat package presence or binary signatures as equivalent to algorithm usage.

### 2. Make epistemic state first-class

Critical fields must support:

- KNOWN
- UNKNOWN
- NOT_OBSERVED
- NOT_APPLICABLE
- INFERRED
- DECLARED
- CONFLICTING

Do not represent epistemically important unknowns merely as NULL.

### 3. Replace scalar coverage with a visibility matrix

Do not produce a single “coverage %” without semantic dimensions.

Track independently:

- artifact coverage
- source coverage
- dependency coverage
- configuration visibility
- deployment visibility
- runtime visibility
- network visibility
- HSM/KMS visibility
- unsupported/failed/timeout targets

Coverage must answer “coverage of what?”

### 4. Add configuration evidence as a first-class source

Support static resolution of:

- application configuration
- environment variables
- config files
- Helm/Kubernetes configuration
- TLS/web-server configuration
- Java security configuration
- service configuration

A source-level crypto call whose algorithm is supplied through configuration should remain unresolved unless the configuration chain can be followed with evidence.

### 5. Upgrade asset relationships into an evidence graph

Every relationship must include:

- relationship type
- provenance
- evidence
- confidence
- discovered / inferred / declared status
- timestamp

Never silently merge source, binary, certificate and network observations.

### 6. Redesign PQC recommendations as candidate migration options

Do not output a single “correct replacement.”

Recommendations must depend on:

- cryptographic function
- purpose
- protocol
- parameter set
- library
- deployment environment
- policy profile
- interoperability
- performance constraints
- implementation availability

For purpose=UNKNOWN, emit “insufficient evidence for purpose-specific recommendation.”

### 7. Rename “cost model” to “migration impact model”

The MVP cannot credibly estimate enterprise dollar cost from byte counts.

Model:

- network overhead
- CPU impact
- memory impact
- certificate/handshake expansion
- compatibility risk
- library/platform support
- migration complexity
- real-time suitability

Allow future organizational cost estimation using supplied enterprise data.

### 8. Make Mosca scenario-based rather than pretending Z is a precise number

Model multiple CRQC scenarios rather than one deterministic date.

For example:

- optimistic
- central
- aggressive

Show:

X + Y > Z

for each scenario and expose sensitivity to X, Y and Z.

The tool must make uncertainty visible rather than convert uncertain forecasts into false-precision numeric risk scores.

### 9. Add temporal inventory support

The data model must support:

- scan snapshots
- historical observations
- deltas
- crypto drift
- newly introduced quantum-vulnerable assets
- removed assets
- changes in certificates
- migration progress

Continuous monitoring can remain deferred, but the schema must not make historical comparison impossible.

### 10. Treat ECDAT itself as a sensitive security platform

Define:

- least privilege
- ephemeral credentials
- sandboxing
- network egress controls
- secret redaction
- evidence encryption
- RBAC
- audit logs
- retention policy
- secure CBOM export

The inventory produced by ECDAT is itself sensitive because it can expose the organization's cryptographic attack surface.

### 11. Change the core product thesis

ECDAT is not primarily a scanner.

It is:

> An evidence correlation and cryptographic migration decision-support layer built on heterogeneous discovery sensors.

The differentiator is not “we scan more files.”

The differentiator is:

> We correlate heterogeneous cryptographic evidence, preserve provenance and uncertainty, quantify quantum-migration risk under explicit assumptions, and produce migration options without pretending that inferred facts are observed facts.

### 12. The canonical demo must prove the full evidence chain

The MVP demonstration should traverse:

Source → dependency → binary → certificate → TLS endpoint → application context → data lifetime → Mosca scenarios → quantum risk → migration options → migration impact → CBOM.

At every transition the UI must show whether the information was:

DISCOVERED / INFERRED / DECLARED / UNKNOWN.

That is the core trust model of ECDAT.

### 13. New judge-proof principle

Every important ECDAT result should answer four questions:

1. What do we believe?
2. What evidence supports it?
3. How confident are we?
4. What remains unknown?

If a result cannot answer those four questions, the architecture is not ready.