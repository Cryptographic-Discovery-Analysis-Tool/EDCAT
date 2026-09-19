#!/usr/bin/env bash
# Provision the Linux build box (Pramana_Ledger_Spec.md §7, Prerequisite).
#
#   "a Linux build box with Docker, Go, Maven, haproxy, SoftHSM2
#    (FACT: OI-007/008/009 -- Semgrep does not install on Windows; images and
#    the Go binary cannot be built here)."
#
# Idempotent: safe to re-run. It installs, it does not remove or reconfigure
# anything it did not install.
#
# Versions are PINNED where the repository has a recorded fixture to validate
# a parser against (tests/fixtures/recorded/<tool>/<version>/). Where apt is
# the only reasonable source, the distribution's version is accepted and
# REPORTED -- the point is that a mismatch is visible, not that it is hidden.
# CLAUDE.md: a parser validated against one version and run against another
# attaches a VisibilityEntry warning; --strict (used by scoring) raises.
#
# Run as root inside the distro:
#   wsl -d Ubuntu -u root -- bash /mnt/c/.../tools/provision/build-box.sh
#
# Network access is required. This is a build box, not the air-gapped target.

set -uo pipefail

# --- pinned versions, from tests/fixtures/recorded/ -------------------------
SEMGREP_VERSION="1.99.0"
SSLYZE_VERSION="6.2.0"
TRIVY_VERSION="0.74.0"
OPENSSL_RECORDED="3.5.4"   # what the fixtures were recorded against

VENV="/opt/pramana-tools"
LOG_PREFIX="[provision]"

say()  { echo "${LOG_PREFIX} $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "${LOG_PREFIX} must run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# --- 1. apt packages ---------------------------------------------------------

APT_PACKAGES=(
  ca-certificates curl gnupg
  docker.io docker-compose-v2   # Docker without Docker Desktop
  golang-go                     # E1: build a stripped Go binary
  maven openjdk-21-jdk-headless # build the Java fixture; run the config-chain answer key
  haproxy                       # a TLS endpoint that actually answers a handshake
  softhsm2 opensc               # P11: PKCS#11 metadata, no key material
  yara                          # P12: constant scanning
  binutils file                 # readelf / strings / file
  python3-venv python3-pip
  jq unzip
)

say "installing apt packages: ${APT_PACKAGES[*]}"
apt-get update -qq
apt-get install -y -qq "${APT_PACKAGES[@]}" || {
  say "ERROR: apt install failed"
  exit 1
}

# --- 2. pinned Python tools in their own venv --------------------------------
#
# Kept out of the system Python: Ubuntu 24.04 marks the system environment
# externally-managed (PEP 668), and pinning a scanner into it would fight the
# package manager on every upgrade.

say "creating ${VENV} and installing pinned Python tools"
python3 -m venv "${VENV}" 2>/dev/null || true
"${VENV}/bin/pip" install --quiet --upgrade pip

# setuptools is pinned below 81 because semgrep 1.99.0 reaches pkg_resources
# through opentelemetry-instrumentation 0.46b0, and setuptools 81 removed
# pkg_resources. Without this, `pip install semgrep==1.99.0` SUCCEEDS and
# `semgrep --version` then dies with ModuleNotFoundError -- an install that
# reports success and produces a broken binary. Observed on Ubuntu 24.04,
# 2026-09-19. Unpin only when semgrep's dependency tree stops needing it.
"${VENV}/bin/pip" install --quiet "setuptools<81"

"${VENV}/bin/pip" install --quiet "semgrep==${SEMGREP_VERSION}" "sslyze==${SSLYZE_VERSION}" || {
  say "ERROR: pinned semgrep/sslyze install failed"
  exit 1
}

# Re-assert the pin: semgrep's own dependency resolution can pull a newer
# setuptools back in.
"${VENV}/bin/pip" install --quiet "setuptools<81"

for tool in semgrep sslyze; do
  ln -sf "${VENV}/bin/${tool}" "/usr/local/bin/${tool}"
done

# --- 3. Trivy, pinned, from the project's own release ------------------------

if [ "$(trivy --version 2>/dev/null | head -1 | awk '{print $2}')" != "${TRIVY_VERSION}" ]; then
  say "installing trivy ${TRIVY_VERSION}"
  ARCH="$(dpkg --print-architecture)"
  case "${ARCH}" in
    amd64) TRIVY_ARCH="Linux-64bit" ;;
    arm64) TRIVY_ARCH="Linux-ARM64" ;;
    *) say "ERROR: unsupported architecture ${ARCH}"; exit 1 ;;
  esac
  TMP="$(mktemp -d)"
  curl -fsSL -o "${TMP}/trivy.tar.gz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
    && tar -xzf "${TMP}/trivy.tar.gz" -C "${TMP}" trivy \
    && install -m 0755 "${TMP}/trivy" /usr/local/bin/trivy
  rm -rf "${TMP}"
fi

# --- 4. Docker daemon --------------------------------------------------------
#
# WSL2 has no systemd by default, so dockerd is started through the sysv
# service script rather than systemctl. Started, not enabled: this script does
# not change the machine's boot behaviour.

if ! docker info >/dev/null 2>&1; then
  say "starting dockerd"
  service docker start >/dev/null 2>&1 || true
  sleep 3
fi

# --- 5. report ---------------------------------------------------------------

echo
say "--- installed versions -------------------------------------------------"
printf '%-14s %s\n' "distro"   "$(lsb_release -ds 2>/dev/null)"
printf '%-14s %s\n' "kernel"   "$(uname -r)"
printf '%-14s %s\n' "docker"   "$(docker --version 2>/dev/null || echo MISSING)"
printf '%-14s %s\n' "compose"  "$(docker compose version 2>/dev/null || echo MISSING)"
printf '%-14s %s\n' "dockerd"  "$(docker info --format '{{.ServerVersion}}' 2>/dev/null || echo 'NOT RUNNING')"
printf '%-14s %s\n' "go"       "$(go version 2>/dev/null || echo MISSING)"
printf '%-14s %s\n' "maven"    "$(mvn -v 2>/dev/null | head -1 || echo MISSING)"
printf '%-14s %s\n' "java"     "$(java -version 2>&1 | head -1 || echo MISSING)"
printf '%-14s %s\n' "haproxy"  "$(haproxy -v 2>/dev/null | head -1 || echo MISSING)"
printf '%-14s %s\n' "softhsm2" "$(softhsm2-util --version 2>/dev/null || echo MISSING)"
printf '%-14s %s\n' "yara"     "$(yara --version 2>/dev/null || echo MISSING)"
printf '%-14s %s\n' "semgrep"  "$(semgrep --version 2>/dev/null || echo MISSING)"
# sslyze has no --version flag; ask pip. (`sslyze --version` prints its usage
# block and exits non-zero, which reads as "not installed" when it is.)
printf '%-14s %s\n' "sslyze"   "$("${VENV}/bin/pip" show sslyze 2>/dev/null | sed -n 2p || echo MISSING)"
printf '%-14s %s\n' "trivy"    "$(trivy --version 2>/dev/null | head -1 || echo MISSING)"
printf '%-14s %s\n' "openssl"  "$(openssl version 2>/dev/null || echo MISSING)"

echo
say "--- pinned vs installed ------------------------------------------------"
check_pin() {
  local name="$1" want="$2" got="$3"
  if [ "${got}" = "${want}" ]; then
    printf '%-10s MATCH     pinned %s\n' "${name}" "${want}"
  else
    printf '%-10s MISMATCH  pinned %s, installed %s\n' "${name}" "${want}" "${got:-none}"
  fi
}
check_pin semgrep "${SEMGREP_VERSION}" "$(semgrep --version 2>/dev/null | tail -1)"
check_pin sslyze  "${SSLYZE_VERSION}"  "$("${VENV}/bin/pip" show sslyze 2>/dev/null | sed -n 2p | awk '{print $2}')"
check_pin trivy   "${TRIVY_VERSION}"   "$(trivy --version 2>/dev/null | head -1 | awk '{print $2}')"
check_pin openssl "${OPENSSL_RECORDED}" "$(openssl version 2>/dev/null | awk '{print $2}')"

echo
say "done. A MISMATCH above is information, not a failure: the adapter will"
say "attach a visibility warning at runtime and --strict will raise, which is"
say "the behaviour CLAUDE.md requires. Record it in docs/open-issues.md."
