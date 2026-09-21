// build-plan.md P17: the API is authenticated now, so every call needs a
// bearer token. DEV_TOKEN matches tools/dev/run_dashboard.py's ECDAT_API_TOKENS
// exactly -- it is a dev-only value committed in plain text on purpose (see
// that script's own docstring for why that is fine here and would not be
// fine anywhere else). A real deployment replaces this file's token source
// with whatever its own login/SSO flow produces; nothing else in this
// dashboard needs to change, because every fetch already goes through
// apiFetch() rather than calling fetch() directly.
export const DEV_TOKEN =
  (typeof window !== 'undefined' && window.ECDAT_API_TOKEN) || 'dev-preview-viewer-token'

export function apiFetch(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${DEV_TOKEN}`,
    },
  })
}
