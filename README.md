# Pramāṇa

Cryptographic discovery and post-quantum migration decision support.

Built for Smart India Hackathon problem statement **SIH26164**.

---

## Requirements

- Python 3.12+
- Node 20+ (dashboard only)
- Docker (optional, for live scanning of the test environment)

## Install and test

```bash
pip install -e ".[dev,api]"
```

```bash
python -m pytest -q
```

## Dashboard

```bash
cd ui/dashboard && npm install && npm run build && cd ../..
```

```bash
python tools/dev/run_dashboard.py
```

Then open <http://127.0.0.1:8000>. The API requires a bearer token; the dev
launcher configures a local-only one. Set `ECDAT_API_TOKENS` for any other
deployment.

## Command line

```bash
python -m ecdat.cli --help
```

## Why "Pramāṇa"

Sanskrit: *the means by which one arrives at valid knowledge.*

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
