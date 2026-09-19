# The TLS prober, shipping its own TLS stack.
#
# Two reasons this is a container rather than a host install:
#
# 1. **Reachability.** Harness H6 puts every live endpoint on an internal
#    Docker network with no egress, so the only honest vantage is a container
#    on that network. `probe_vantage` is recorded per probe (Lock §5 row 1),
#    and "the host, via a hole punched through the isolation" is not a vantage
#    any deployment would have.
# 2. **Reproducibility.** OI-014: the build box carries OpenSSL 3.0.13, which
#    cannot even name X25519MLKEM768, while the endpoint's container carries
#    3.5.8. A prober that inherits whatever TLS library its host distribution
#    ships produces results that depend on the host, which is not a scanner --
#    it is a lottery. This image pins its own.
#
# sslyze is AGPL-3.0. Pramana invokes it as a SEPARATE PROCESS and ships its
# full source, which is the boundary the licence requires
# (Pramana_Ledger_Spec.md §3, row "TLS").

FROM python:3.12-slim-bookworm

# Pinned to the version tests/fixtures/recorded/sslyze/6.2.0/ was recorded
# against, so the parser runs against the build it was validated on.
ARG SSLYZE_VERSION=6.2.0

RUN pip install --no-cache-dir "sslyze==${SSLYZE_VERSION}"

# Report the TLS stack this image actually carries. The version matters to
# every result the prober produces, so it is printed, not assumed.
RUN python -c "import ssl; print('prober OpenSSL:', ssl.OPENSSL_VERSION)"

ENTRYPOINT ["sslyze"]
