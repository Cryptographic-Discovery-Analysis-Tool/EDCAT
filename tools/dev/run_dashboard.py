"""Local dashboard launcher (build-plan.md P17).

`api/app.py`'s module-level `app = create_app()` is secure by default: with
no `ECDAT_API_TOKENS` set, `TokenRegistry.from_env()` is empty and every
request is refused. That is deliberate -- see security/auth.py's module
docstring -- and this script exists so a local preview does not have to
weaken it.

This sets ONE well-known, clearly-labelled dev token before importing the
app, then runs uvicorn exactly the way `.claude/launch.json`'s `pramana`
entry otherwise would. `ui/dashboard/src/api.js` reads the SAME token so the
built dashboard can call the now-protected API without a login flow -- a
real login UI is out of build-plan.md P17's stated "minimum honest scope"
(an authenticated API, roles, an audit log), not something this script
pretends to add.

Never run this in anything but a local preview: the token is committed to
this repository in plain text, which is the opposite of a secret.
"""
from __future__ import annotations

import json
import os

#: Matches ui/dashboard/src/api.js's DEV_TOKEN exactly. EXPORTER rather than
#: VIEWER so the one dev token can drive every panel the built dashboard
#: has, including the export button (EXPORTER implies VIEWER -- see
#: security/auth.py's Role._IMPLIES). A real deployment sets its own
#: ECDAT_API_TOKENS, with separate viewer and exporter tokens, before
#: starting uvicorn, and never imports this script.
DEV_TOKEN = "dev-preview-viewer-token"

os.environ.setdefault(
    "ECDAT_API_TOKENS", json.dumps({DEV_TOKEN: "EXPORTER"})
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ecdat.api.app:app", port=8000)
