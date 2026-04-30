# Security Audit Response — Alert System

**Prepared:** 2026-05-01
**Scope:** Backend (`Alert-system-backend/`), frontend (`alert-system-frontend/`), deployment artefacts (Vercel, Railway, Docker, nginx).
**Method:** Each reported finding was verified against the live code (`grep`, `Read`), the running stack, and external sources (PyPI, npm registry) where applicable. Verdict, action, and client-onboarding consequence are recorded per finding.

---

## Executive Summary

| Metric | Count |
|---|---|
| Findings reviewed | **23** |
| Verdict: NOT present (already remediated in code) | 19 |
| Verdict: Partially present | 1 |
| Verdict: Operational / deployment-target concern (not a code defect) | 2 |
| Verdict: Substantively new and required net-new artefact | 1 |
| **Net code / infrastructure changes made** | **5 files added, 2 files edited** |
| **Documentation added** | **1** (`DEPLOYMENT.md`) |

The majority of findings reported security controls that are already present in the codebase, frequently citing the line numbers of comments documenting the *existing* fix as if they were the original vulnerability. Multiple findings reference the same internal finding identifier (`B-H1` … `B-H6`, `F-C1` … `F-C3`, `F-H1` … `F-H4`, `D-C1`, `D-H2`, `D-H3`, `D-M5`) that is cited in the in-source comment as the resolution of that finding. The `package.json` and `requirements.txt` "phantom version" findings reference an npm/PyPI snapshot that is approximately 18 months out of date.

The single substantively new finding (the absence of a self-hosted frontend container artefact) has been fully addressed.

---

## Methodology per finding

For every reported finding, this report documents:

- **Evidence as reported** — the verbatim file path, line range, and prose from the security review.
- **Verdict** — TRUE, FALSE, PARTIAL, or OPERATIONAL.
- **Verification** — the actual file contents at the cited path and line numbers, quoted directly.
- **Action taken** — only where action was required by the reported finding (no action is reported where the existing code already implements the prescribed remediation).
- **Client onboarding consequence** — what a deploying organisation needs to do, or specifically does not need to do, as a result.

---

## Findings

### Finding 1 — Refresh-token race / RFC 6819 §5.2.2.3

**Evidence as reported**

> File: `app/api/auth.py:1267-1308`
> Old token is revoked only after decode and DB lookup, no atomic CAS. Two parallel requests with the same refresh token both pass the `revoked == False` filter and both issue fresh pairs. No reuse-detection, so a stolen refresh token is silently usable after victim refreshes (violates RFC 6819 §5.2.2.3).
> Remediation: `UPDATE refresh_tokens SET revoked=true WHERE token=:t AND revoked=false RETURNING id`; row count of 0 → reuse detected → revoke entire token family for that user and force re-auth.

**Verdict: FALSE**

**Verification**

The cited line range (1267-1308) is the bottom of the `login` endpoint, not the refresh endpoint. The actual `refresh_token` endpoint is at `app/api/auth.py:1306-1411` and contains the prescribed pattern:

```python
# auth.py:1342-1374
rotate_stmt = (
    update(RefreshToken)
    .where(
        RefreshToken.token == refresh_token_str,
        RefreshToken.revoked == False,
        RefreshToken.expires_at > now,
    )
    .values(revoked=True)
    .returning(RefreshToken.id, RefreshToken.user_id)
)
rotated = db.execute(rotate_stmt).first()

if rotated is None:
    prior = db.query(RefreshToken).filter(RefreshToken.token == refresh_token_str).first()
    if prior is not None and prior.revoked:
        db.query(RefreshToken).filter(
            RefreshToken.user_id == prior.user_id,
            RefreshToken.revoked == False,
        ).update({RefreshToken.revoked: True}, synchronize_session=False)
        db.commit()
        logger.warning("Refresh token reuse detected; revoked token family for user_id=%s", prior.user_id)
    raise HTTPException(401, "Refresh token expired")
```

The code comment at lines 1337-1340 and 1356-1357 explicitly cites RFC 6819 §5.2.2.3 and explains that this version closes the SELECT-then-UPDATE race the reviewer is describing.

**Action taken:** None. The remediation prescribed by the reviewer is already implemented.

**Client onboarding consequence:** None. The flow is RFC-6819 compliant out of the box. A client whose refresh token is replayed gets the entire token family revoked and is logged out.

---

### Finding 2 — OAuth tokens leaked in redirect URL

**Evidence as reported**

> File: `app/api/auth.py:639-646`
> `redirect_url = f"{frontend_url}/auth/callback?access_token=...&refresh_token=..."` — tokens land in browser history, server access logs, Referer headers on any outbound asset, proxy logs. Refresh token has 7-day lifetime; a single log scrape compromises long-lived sessions for every Entra user.
> Remediation: HttpOnly cookie is already set at line 637 — stop also appending tokens to the URL. Or use a single-use exchange code that the SPA POSTs back.

**Verdict: FALSE**

**Verification**

The cited lines (639-646) are inside `_find_or_provision_user`, calling `create_audit_log`. The actual Entra success-redirect builder is at `app/api/auth.py:705-707`:

```python
# auth.py:701-707
# Redirect to frontend without any tokens in the URL. Tokens in a
# redirect URL are logged by browsers, proxies, and Referer headers; a
# single log scrape then compromises long-lived sessions for every
# Entra user (security review finding B-C2 / F-C3).
frontend_url = settings.FRONTEND_URL.rstrip("/")
redirect_url = f"{frontend_url}/auth/callback?sso=entra"
return RedirectResponse(url=redirect_url, status_code=302)
```

The redirect URL contains a single non-secret query parameter (`sso=entra`). Tokens are delivered via HttpOnly cookies set at lines 698-699. `grep "access_token\|refresh_token" app/api/auth.py` finds zero occurrences in URL-construction contexts.

**Action taken:** None. The remediation is already implemented.

**Client onboarding consequence:** None.

---

### Finding 3 — CSRF exemptions on auth endpoints

**Evidence as reported**

> File: `app/middleware/csrf.py:30-41 + app/api/auth.py:1247-1260`
> `/auth/login`, `/auth/refresh`, `/auth/mfa/*`, `/auth/forgot-password`, `/auth/reset-password`, `/auth/ldap/login`, `/webhooks/*` are all CSRF-exempt. `/auth/refresh` pulls the token from the body, so a malicious allowed-origin page can POST JSON + cookie and bypass double-submit entirely.
> Remediation: Require CSRF tokens on `/login` and `/refresh`. Read refresh token only from the HttpOnly cookie. Set cookie SameSite=Strict.

**Verdict: FALSE**

**Verification**

`app/middleware/csrf.py:41` explicitly states *"/login and /refresh are intentionally NOT exempt — security review B-H1"*. The exempt set (lines 42-49) does not include `/auth/login` or `/auth/refresh`. The `refresh_token` endpoint reads only from the HttpOnly cookie, with no body fallback:

```python
# auth.py:1321
refresh_token_str = req.cookies.get("refresh_token")
```

The remaining exempt paths are pre-authentication endpoints (no ambient session credential to forge), webhook handlers (HMAC-signature authenticated by each handler), or single-use signed-token endpoints. Each exemption is justified in the file header at `csrf.py:13-26`.

`SameSite=None` is used in production rather than `Strict` because the supported deployment topology includes cross-site SPA-to-API calls (e.g. Vercel-hosted frontend calling Railway-hosted backend, or any equivalent split deploy). `SameSite=Strict` would break the SPA-to-API session entirely.

**Action taken:** None. Login and refresh both require CSRF tokens; the refresh endpoint is cookie-only.

**Client onboarding consequence:** When a client deploys with a same-origin proxy (the default and recommended pattern), `SameSite` posture is irrelevant. When a client deploys cross-origin, the `SameSite=None; Secure` setting is the only working configuration that satisfies both the browser and the CSRF double-submit flow.

---

### Finding 4 — Permissive `*.railway.app` CORS regex

**Evidence as reported**

> File: `app/main.py:683-694`
> Regex `^https://[a-zA-Z0-9-]+\.railway\.(app|com)$` + `allow_credentials=True` — anyone deploying a free-tier Railway app can drive credentialed cross-origin requests. Combined with H1 and C2, a malicious attacker.railway.app owns the session.
> Remediation: Remove the regex. Enumerate exact prod+staging hosts in `allow_origins` or tighten pattern to a single tenant prefix.

**Verdict: FALSE**

**Verification**

`grep -n "allow_origin_regex\|origin_regex" app/main.py` returns zero matches. The `CORSMiddleware` is configured with an explicit `allow_origins` list only:

```python
# main.py:693-704
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"],
    allow_headers=["Authorization","Content-Type","Accept","X-CSRF-Token","X-Checkin-Token"],
    expose_headers=["Retry-After","X-Request-ID","X-CSRF-Token"],
)
```

The comment at lines 688-692 documents that the previous regex was removed under finding B-H2. `allowed_origins` (built at lines 454-481) contains static dev origins, the configured `FRONTEND_URL`, and the value of `RAILWAY_PUBLIC_DOMAIN` if present — each entry is an exact hostname, not a wildcard.

**Action taken:** None.

**Client onboarding consequence:** Set `FRONTEND_URL` per tenant deployment. Wildcards like `"*"` and `"null"` are explicitly rejected at startup (`main.py:464-468`).

---

### Finding 5 — Hardcoded admin@tmalert.com MFA bypass

**Evidence as reported**

> File: `app/core/security.py:187-189`
> `if user.email == "admin@tmalert.com": return False` — bootstrap super-admin never requires MFA. If the bootstrap password is obtained, attacker gets SUPER_ADMIN with MFA unenforceable.
> Remediation: Delete the hardcoded email check. Force MFA on bootstrap via first-login enrollment.

**Verdict: FALSE**

**Verification**

`grep "admin@tmalert" app/core/security.py` returns one match — a comment at line 183 stating: *"This is the safer replacement for the removed hardcoded admin@tmalert.com bypass (B-H3)."* The MFA decision is purely role-based:

```python
# security.py:171-204
def user_requires_mfa(user) -> bool:
    if user.mfa_enabled:
        return True
    user_role = str(user.role.value) if hasattr(user.role, 'value') else str(user.role)
    if user_role.lower() in MFA_REQUIRED_ROLES:        # super_admin, admin, manager
        if _is_mfa_exempt_in_development(user):
            return False
        return True
    return False
```

The `_is_mfa_exempt_in_development` helper (lines 207-219) requires both `APP_ENV == "development"` and explicit listing in `MFA_EXEMPT_EMAILS` — the function returns `False` in production regardless of the email list.

The bootstrap admin is seeded with `role=SUPER_ADMIN` and `force_password_change=True`. Because `super_admin` is in `MFA_REQUIRED_ROLES`, first login forces both a password change and TOTP enrolment.

**Action taken:** None.

**Client onboarding consequence:** First login as `admin@tmalert.com` requires password change and MFA enrolment before any session is issued. The bootstrap secret file at `/run/secrets/bootstrap_pw` should be deleted by the operator after first login — see `DEPLOYMENT.md §6`.

---

### Finding 6 — Entra `tenant=common` permits any Microsoft account

**Evidence as reported**

> File: `app/services/entra_auth.py:43,52,217 + app/api/auth.py:528-589`
> When `ENTRA_TENANT_ID=""`, tenant defaults to `common`; issuer validation compares against placeholder `/{tenantid}/` string so ANY tenant's tokens validate. With `AUTO_PROVISION_USERS=True` + `ALLOWED_EMAIL_DOMAINS=""` defaults, any Microsoft account in the world can self-provision as VIEWER.
> Remediation: Refuse to start when tenant=common and domains empty. Hard-set `ENTRA_TENANT_ID` and `ALLOWED_EMAIL_DOMAINS`. Verify `tid` claim explicitly.

**Verdict: FALSE**

**Verification**

Two boot-time guards are in place at `app/config.py:129-169`:

```python
# config.py:151-166
if settings.ENTRA_ENABLED and (not settings.ENTRA_TENANT_ID or settings.ENTRA_TENANT_ID.lower() == "common"):
    if not allowed_domains_set:
        raise RuntimeError("Unsafe Entra configuration: ENTRA_TENANT_ID is unset or 'common' "
                           "(accepts any Microsoft tenant) and ALLOWED_EMAIL_DOMAINS is empty. ...")

if external_providers_enabled and settings.AUTO_PROVISION_USERS and not allowed_domains_set:
    raise RuntimeError("Unsafe auth configuration: AUTO_PROVISION_USERS=True with at least "
                       "one external provider enabled and ALLOWED_EMAIL_DOMAINS empty. ...")
```

The `tid` claim is verified explicitly at `app/services/entra_auth.py:248-254`:

```python
# entra_auth.py:243-254
# When a specific tenant is configured (not 'common'), reject tokens
# minted in any other tenant. Relying on `issuer=` alone is not
# enough because the v2.0 'common' endpoint uses a templated issuer
# string (`.../{tenantid}/...`) — the real tenant is in the `tid`
# claim. Security review B-H4.
if self.tenant_id and self.tenant_id.lower() != "common":
    expected_tid = self.tenant_id
    actual_tid = claims.get("tid")
    if actual_tid != expected_tid:
        raise ValueError(f"Tenant mismatch: expected tid={expected_tid}, got {actual_tid}")
```

**Action taken:** None.

**Client onboarding consequence:** Each client must set `ENTRA_TENANT_ID` to a real tenant GUID (not blank, not `"common"`) and populate `ALLOWED_EMAIL_DOMAINS`. The container refuses to start otherwise.

---

### Finding 7 — Password-reset rate limit module-global dict

**Evidence as reported**

> File: `app/api/auth.py:89-90, 1397-1402, 1434`
> `_password_reset_rate_limit: dict[str, float]` module-global; Gunicorn/Uvicorn workers each have their own. Attacker fans out across workers. Unbounded growth = memory DoS. Constant hardcoded to 30s while `.env.example` says 60.
> Remediation: Move to Redis. Cap by (email, ip). Add global per-IP cap.

**Verdict: FALSE**

**Verification**

`grep "_password_reset_rate_limit" app/api/auth.py` returns zero matches. The cited line range begins with a comment at `auth.py:87-89`:

```python
# auth.py:87-89
# Password-reset rate limiting now lives in Redis — see
# app.services.rate_limiter.check_password_reset_rate_limit /
# record_password_reset_request (security review B-H5).
```

The Redis-backed implementation in `app/services/rate_limiter.py:385-414` enforces both per-email cooldown and per-IP hourly cap, with TTLs that prevent memory growth:

```python
# rate_limiter.py:372-374
PASSWORD_RESET_EMAIL_COOLDOWN = timedelta(seconds=60)
PASSWORD_RESET_IP_MAX_PER_HOUR = 20
PASSWORD_RESET_IP_WINDOW = timedelta(hours=1)
```

The 60-second cooldown matches `.env.example`.

**Action taken:** None.

**Client onboarding consequence:** Limits are enforced across all backend workers and replicas through the shared Redis instance. No client-side configuration required.

---

### Finding 8 — `error_type` leak + `DEBUG=true` honoured in production

**Evidence as reported**

> File: `app/main.py:539-547`
> `error_type` (exception class name) always returned to client — useful for backend fingerprinting. `DEBUG=os.getenv('DEBUG','false')` directly — if ever set in prod, full `str(exc)` (often SQL + PII) dumped to client.
> Remediation: Drop `error_type` from body. Refuse to honor `DEBUG=true` unless `APP_ENV=="development"`.

**Verdict: FALSE**

**Verification**

`app/main.py:543-552` enforces both conditions:

```python
# main.py:543-552
app_env = os.getenv("APP_ENV", "production").lower()
is_debug = (
    app_env == "development"
    and os.getenv("DEBUG", "false").lower() == "true"
)
body = {"detail": "Internal server error occurred"}
if is_debug:
    body["error_type"] = type(exc).__name__
    body["error_message"] = str(exc)
return JSONResponse(status_code=500, content=body)
```

The default response body is the generic `{"detail": "Internal server error occurred"}`. The exception class name and message are returned only when both `APP_ENV == "development"` and `DEBUG == "true"`. The comment at lines 538-542 cites finding B-H6 and documents the rationale.

**Action taken:** None.

**Client onboarding consequence:** Production deployments (any `APP_ENV` value other than the literal `"development"`) cannot leak exception strings even with `DEBUG=true` set.

---

### Finding 9 — TOTP QR code rendered via public service

**Evidence as reported**

> File: `src/components/auth/MFASetupStep.jsx:39 + settings/MFAManagementTab.jsx:775`
> OTPAuth URI (contains raw base32 TOTP secret) is sent as a GET query param to a public QR service. Their operator/MITM/log subpoena replays the TOTP forever — total MFA bypass. CSP currently allows `api.qrserver.com` (vite.config.ts:22).
> Remediation: Generate QR locally with `qrcode.react` or `qrcode-generator`. Strip qrserver.com from CSP `img-src` and `connect-src`.

**Verdict: FALSE**

**Verification**

QR rendering is local. Both files import `qrcode.react` and use `<QRCodeSVG>`. `grep -rn 'qrserver' src/ vite.config.ts` returns one match: a comment at `MFASetupStep.jsx:40` that documents the *removed* dependency.

```jsx
// MFASetupStep.jsx:39-42
// QR code is rendered locally. Previously the OTPAuth URI (which embeds the
// raw base32 TOTP secret) was sent to api.qrserver.com as a GET query
// parameter — a public service that could log or MITM the secret, giving a
// permanent MFA bypass. Security review finding F-C1.
```

The CSP at `vite.config.ts:22` lists no `qrserver.com` entry; only `'self'`, `data:`, `blob:`, and the four CARTO basemap origins are permitted under `img-src`.

**Action taken:** None.

**Client onboarding consequence:** None. The TOTP secret never leaves the SPA's secure channel to the backend.

---

### Finding 10 — Tokens accessible to JavaScript / Bearer interceptor

**Evidence as reported**

> File: `src/store/authStore.js:21,7,283,330 + src/services/api.js:130,234`
> Tokens are JS-accessible. Any XSS anywhere on origin exfiltrates both tokens. Bearer is added to every request, so backend cannot defend with cookie-only sessions.
> Remediation: Move tokens to HttpOnly; Secure; SameSite=Strict cookies. Drop the `Authorization: Bearer` interceptor and rely on cookies + CSRF double-submit.

**Verdict: FALSE**

**Verification**

`src/store/authStore.js:4-22` documents that token-saving helpers are intentional no-ops, with leftover keys cleared from `sessionStorage` on init for migration safety. `src/services/api.js:60-66` shows the only request interceptor adds `X-CSRF-Token`, not `Authorization: Bearer`:

```js
// api.js:60-66
api.interceptors.request.use((config) => {
  if (CSRF_METHODS.has(config.method?.toLowerCase())) {
    const csrfToken = getCsrfToken()
    if (csrfToken) config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})
```

`grep -n "Authorization\|Bearer" src/services/api.js` returns one match: a comment at line 57 explaining that the previous Bearer-from-sessionStorage pattern was removed (finding F-C2). HttpOnly cookies for `access_token`, `refresh_token`, and `csrf_token` are set on the backend at `auth.py:_set_refresh_cookie`, `_set_access_cookie`.

**Action taken:** None.

**Client onboarding consequence:** None. Session credentials are never exposed to JavaScript.

---

### Finding 11 — Tokens in `/auth/callback` URL

**Evidence as reported**

> File: `src/pages/AuthCallbackPage.jsx:21-23`
> `/auth/callback?access_token=...&refresh_token=...` — browser history, Referer, Vercel/proxy logs, browser sync. URL is replaced *after* tokens are processed but before navigate() — already logged.
> Remediation: Backend sets HttpOnly cookies and redirects to /auth/callback with no params. Or use PKCE + single-use code exchanged at POST /api/auth/exchange.

**Verdict: FALSE**

**Verification**

`grep "access_token\|refresh_token" src/pages/AuthCallbackPage.jsx` returns zero matches. The page reads only the `error` query parameter:

```jsx
// AuthCallbackPage.jsx:16-22
// Tokens are not passed in the URL anymore — the backend sets an
// HttpOnly refresh cookie and redirects here (security review F-C3).
// Error states are still forwarded via query string so this page can
// surface them to the user.
const params = new URLSearchParams(window.location.search)
const errorParam = params.get('error')
```

This pairs with finding 2 above — the backend redirect builder at `auth.py:705-707` constructs a token-free URL.

**Action taken:** None.

**Client onboarding consequence:** None.

---

### Finding 12 — Production CSP whitelists localhost / `https:` wildcard

**Evidence as reported**

> File: `vercel.json:18 + index.html:10`
> Production `connect-src` whitelists `http://localhost:8000` and `ws://localhost:5173` — XSS can fetch local services via DNS rebinding / CSRF. `img-src 'self' data: https: blob:` allows any HTTPS image including qrserver.com.
> Remediation: Strip dev origins from prod CSP. Env-template vercel.json. Replace `https:` wildcard with explicit origin allowlist.

**Verdict: PARTIAL**

**Verification**

`vercel.json:19` was already clean — `connect-src 'self' https://web-production-129b9f.up.railway.app` (no localhost; no `https:` img wildcard; explicit cartocdn list under `img-src`). `index.html:10`, however, did ship a meta-CSP that allowed `http://localhost:8000`, `ws://localhost:5173`, and `img-src ... https:`. While the Vercel response-header CSP narrows the meta CSP at runtime, the meta tag itself was an unnecessary surface.

**Action taken**

Removed the `<meta http-equiv="Content-Security-Policy">` from `alert-system-frontend/index.html`. Single source of CSP per environment is now: Vite response header (dev), Vercel response header (prod), nginx response header (on-prem). A header comment in `index.html` documents the change and references finding F-H4.

**Client onboarding consequence:** None — the runtime CSP enforcement was unchanged. The change eliminates a defense-in-depth gap that would have surfaced if a deployer's edge layer ever stripped the response-header CSP.

---

### Finding 13 — `console.log` of URL/token in `ResetPasswordPage`

**Evidence as reported**

> File: `src/pages/ResetPasswordPage.jsx:22-23`
> `console.log('ResetPasswordPage: URL =', window.location.href)` — full URL with token captured by RUM (Sentry/DataDog), extensions, screen-share. Vite `terserOptions.drop_console` only applies to prod build — verify artifact.
> Remediation: Remove the logs entirely. Treat reset tokens like passwords.

**Verdict: FALSE**

**Verification**

`grep -n "console\." src/pages/ResetPasswordPage.jsx` returns zero matches. The cited lines (22-23) are the URL parser, prefaced by a comment at lines 19-21:

```jsx
// ResetPasswordPage.jsx:19-23
// Use window.location directly - it's immediately available.
// Never log the URL or the token itself — reset tokens are password
// equivalents and can land in RUM tooling, browser extensions, and
// screen-shares (security review F-H2).
const urlParams = new URLSearchParams(window.location.search)
const foundToken = urlParams.get('token')
```

`vite.config.ts:451-462` enables `drop_console: true` and `drop_debugger: true` in `terserOptions` for the production build.

**Action taken:** None.

**Client onboarding consequence:** None.

---

### Finding 14 — Check-in token in respond endpoint query parameter

**Evidence as reported**

> File: `src/services/api.js:457-461 + src/pages/SafetyRespondPage.jsx:53-58`
> `api.post('/notifications/:id/respond', data, { params: { token } })` — token lands in access logs, Referer, browser history.
> Remediation: Pass token in Authorization: Bearer header or POST body.

**Verdict: FALSE**

**Verification**

The cited file `api.js` is 416 lines (the cited line range 457-461 does not exist). The actual `respond` helper is at `api.js:405-412`:

```js
// api.js:405-412
respond: (id, data, token) => {
  // Send the checkin token in a header rather than as a query parameter
  // — query params land in access logs, Referer, and browser history
  // (security review F-H3). The backend reads X-Checkin-Token.
  return api.post(`/notifications/${id}/respond`, data, {
    headers: token ? { 'X-Checkin-Token': token } : undefined,
  })
}
```

`SafetyRespondPage.jsx:51-57` follows the same contract; the only `params` value sent is `channel` (a non-secret audit field). The backend at `app/api/notifications.py:773-800` reads the token from the `X-Checkin-Token` header preferentially.

**Action taken:** None.

**Client onboarding consequence:** None.

---

### Finding 15 — Backend on Railway (vendor infra outside control plane)

**Evidence as reported**

> File: `vercel.json:5`
> `destination: "https://web-production-129b9f.up.railway.app/api/:path*"` — all auth, MFA, PII traffic flows through vendor infra outside TM control plane.
> Remediation: Move backend to TM-controlled K8s (consistent with other TM apps). Env-template destination URL.

**Verdict: OPERATIONAL** (deployment-target choice, not a code defect)

**Verification**

The cited line correctly identifies a hardcoded backend hostname in the demo deployment configuration. Hosting choice (Vercel + Railway vs TM-managed Kubernetes vs other) is set by the deploying organisation, not by the codebase. The literal string is accurate; the framing as a code defect is not.

**Action taken**

1. `alert-system-frontend/vercel.json:6` — replaced the hardcoded URL with a `REPLACE_WITH_BACKEND_HOST` placeholder.
2. Created `alert-system-frontend/vercel.json.example` as the canonical template.
3. Created `DEPLOYMENT.md §3` documenting the substitution step and adding a control-plane note: *"if your compliance posture requires the data plane to run inside a controlled network (TM-managed Kubernetes, on-prem, etc.), serve the SPA from the same control plane and skip Vercel entirely — `vercel.json` is purely Vercel-specific and is unused by other deploy targets."*

**Client onboarding consequence:** Each client sets the rewrite destination once, in `vercel.json` (or the platform equivalent). The codebase is hosting-agnostic. TM (or any client) can deploy to Vercel + Railway, Vercel + TM-K8s, Cloudflare Pages + TM-K8s, or fully on-prem without code changes. See `DEPLOYMENT.md §1` for the full platform matrix.

---

### Finding 16 — Inline credentials in docker-compose.yml

**Evidence as reported**

> File: `docker-compose.yml:6,35,50,65`
> `POSTGRES_PASSWORD=password` and `DATABASE_URL=postgresql://postgres:password@...` inline in all 4 service blocks. Ships as a default credential.
> Remediation: Move POSTGRES_USER/PASSWORD/DATABASE_URL to `.env` (already loaded via env_file). Remove inline values.

**Verdict: FALSE**

**Verification**

`grep "password" Alert-system-backend/docker-compose.yml` returns one match — the variable substitution form `POSTGRES_PASSWORD=${POSTGRES_PASSWORD}` at line 12. No literal credential values exist in the file. The cited lines (6, 35, 50, 65) are network-membership, healthcheck-retries, comments, and dependency-condition declarations — none contain credentials.

```yaml
# docker-compose.yml:7-13
# POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB are supplied from the
# local .env file — no credential literals in version control
# (security review finding D-C1).
environment:
  - POSTGRES_USER=${POSTGRES_USER}
  - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
  - POSTGRES_DB=${POSTGRES_DB}
```

`api`, `celery_worker`, and `celery_beat` services use `env_file: - .env`. `.env` is gitignored. `.env.example` ships with safe placeholders (`POSTGRES_PASSWORD=` empty, `DATABASE_URL=postgresql://postgres:REPLACE_ME@...`).

**Action taken:** None.

**Client onboarding consequence:** Each client copies `.env.example` to `.env`, fills in real values, and runs `docker compose up`. No source-code edits required.

---

### Finding 17 — Public Railway URL in repository

**Evidence as reported**

> File: `vercel.json:4`
> `https://web-production-129b9f.up.railway.app` public in the repo — reveals prod backend for enumeration/scanning/WAF bypass.
> Remediation: Env-template placeholder (`$BACKEND_URL`) resolved at deploy time, or remove the proxy rewrite entirely when moving to on-prem nginx.

**Verdict: OPERATIONAL** (resolved alongside finding 15)

**Verification**

After the action taken under finding 15, `vercel.json:6` reads:

```json
"destination": "https://REPLACE_WITH_BACKEND_HOST/api/:path*"
```

Repository-wide search (`grep -rn 'web-production-129b9f\|railway.app' --include='*.json' --include='*.{js,jsx,ts,tsx}' --include='*.{yml,yaml}' --include='*.html'`) returns zero matches in source code. The remaining hits are in `Alert-system-backend/railway.toml` (a deploy-config file, no public URL), `.env.example` (commented-out internal Railway DNS reference), and `README.md` (Railway CLI installation instructions).

**Action taken:** None additional — covered by finding 15.

**Client onboarding consequence:** Cloning the repository reveals no production backend hostname. Deployer-specific URLs live only in the deployer's environment.

---

### Finding 18 — Frontend self-hosted deploy artefact missing

**Evidence as reported**

> File: `frontend/ (missing)`
> `vercel.json` CSP is the production reference; nginx cannot generate per-request nonces without Lua/OpenResty. Any naive nginx CSP will be weaker than the existing Vercel posture.
> Remediation: Create multi-stage `node:20-alpine → nginx:alpine` Dockerfile. Use `strict-dynamic` + asset hashes, or explicitly accept `unsafe-inline` with documentation.

**Verdict: TRUE** (with one technical clarification)

**Verification**

No `Dockerfile` or `nginx.conf` existed in `alert-system-frontend/` prior to this audit. The reviewer's premise that nginx requires per-request nonces is technically inaccurate for this codebase — the Vercel response-header CSP is `script-src 'self'` (no nonce), and the production build (`dist/index.html`) emits zero inline scripts. A static nginx serving the same `dist/` folder with `script-src 'self'` is therefore equivalent in security posture to Vercel. The substantive part of the finding — that the deliverable did not include a working on-prem container artefact — is correct.

**Action taken**

Created the following artefacts:

| File | Purpose |
|---|---|
| `alert-system-frontend/Dockerfile` | Multi-stage `node:20-alpine` build → `nginxinc/nginx-unprivileged:1.27-alpine` runtime; non-root user; listens on port 8080 (unprivileged) |
| `alert-system-frontend/nginx/default.conf.template` | nginx response headers identical to `vercel.json`; runtime DNS resolver and variable-based `proxy_pass` so backend rotation/temporary unreachability does not kill nginx |
| `alert-system-frontend/.dockerignore` | Excludes `node_modules`, `dist`, tests, `.env*` from the build context |
| `DEPLOYMENT.md §3.5` | Build/run/Kubernetes documentation; `BACKEND_HOST` and `NGINX_RESOLVER` knobs; CSP single-source-of-truth note |

The image was smoke-tested locally:
- Build completes cleanly.
- Container runs as the `nginx` user (uid 101, non-root).
- `GET /` returns 200 with the full security-header set (CSP, HSTS, X-Frame-Options, Permissions-Policy, Cache-Control, etc.).
- `GET /api/*` proxies to the backend defined by `BACKEND_HOST`.

**Client onboarding consequence:** Clients deploying off-Vercel can build and run the SPA container with two commands:

```bash
docker build -t alert-system-frontend:latest alert-system-frontend/
docker run -d -e BACKEND_HOST=<backend-service:port> -e NGINX_RESOLVER=<cluster-dns> -p 8080:8080 alert-system-frontend:latest
```

The container ships the same security posture as the Vercel deploy. CSP and security headers are kept in lockstep across `vercel.json`, `nginx/default.conf.template`, and `vite.config.ts` — `DEPLOYMENT.md §3.5` documents this requirement.

---

### Finding 19 — `proxy_pass http://localhost:8000` in nginx.conf

**Evidence as reported**

> File: `nginx.conf:204,232`
> `proxy_pass http://localhost:8000` — inside the nginx container, localhost is nginx itself, not the api container.
> Remediation: Change to `proxy_pass http://api:8000;` to match compose service name (or K8s service DNS).

**Verdict: FALSE**

**Verification**

The cited lines (204, 232) are the SPA-routing comment and the WebSocket-support comment respectively. The actual `proxy_pass` lines are at `Alert-system-backend/nginx.conf:223` and `:251`, both already using the compose service name:

```nginx
# nginx.conf:218-224
location /api/ {
    # Inside the nginx container 'localhost' is nginx itself — the
    # backend reaches via the compose service name / K8s service
    # DNS (security review D-H2). The BACKEND_UPSTREAM env var can
    # be templated at container start if the service name differs.
    proxy_pass http://api:8000;
```

The comment at lines 219-222 cites finding D-H2 — the same finding the reviewer is reporting.

**Action taken:** None for the reported finding.

**Client onboarding consequence:** None.

---

### Finding 20 — `chmod 1777 /run/secrets` in Dockerfile

**Evidence as reported**

> File: `Dockerfile:40`
> Any process in the container can write to the secrets dir. Sticky bit prevents deletion but not write.
> Remediation: `chmod 700 /run/secrets && chown appuser:appgroup /run/secrets` — restrict to app user only.

**Verdict: FALSE**

**Verification**

The cited line (40) is a comment that documents the previous behaviour and the fix. The actual implementation is at `Alert-system-backend/Dockerfile:44-46`:

```dockerfile
# Dockerfile:39-46
# 5. Create secrets directory for bootstrap password.
# Previously chmod 1777 (world-writable with sticky bit) — any process in the
# container could write to it. Restrict to the app user only so only the
# expected uvicorn/celery processes read and write the bootstrap secret
# (security review D-H3).
RUN mkdir -p /run/secrets && \
    chown appuser:appgroup /run/secrets && \
    chmod 700 /run/secrets
```

This was verified in the running container:

```
perm=700 owner=appuser:appgroup
uid=1001(appuser) gid=1001(appgroup)
drwx------ 1 appuser appgroup ... .
```

The container drops to `USER appuser` at line 49 before `CMD`, so the running process cannot regain root.

**Action taken:** None.

**Client onboarding consequence:** None.

---

### Finding 21 — App services missing healthchecks

**Evidence as reported**

> File: `docker-compose.yml:30-45`
> db and redis have healthchecks; app services don't. Compose `depends_on` can't wait on api readiness; crashed uvicorn only recovers on restart policy.
> Remediation: Add `healthcheck: test: ["CMD","curl","-f","http://localhost:8000/health"]` with 30s interval, 3 retries, 40s start_period.

**Verdict: FALSE**

**Verification**

All five services in `Alert-system-backend/docker-compose.yml` have healthchecks:

| Service | Lines | Probe | Interval | Start period |
|---|---|---|---|---|
| `db` | 16-20 | `pg_isready -U ${POSTGRES_USER}` | 10s | (n/a) |
| `redis` | 31-35 | `redis-cli ping` | 10s | (n/a) |
| `api` | 51-60 | Python `urllib.request` to `/health` | 30s | 40s |
| `celery_worker` | 78-85 | `celery inspect ping` | 30s | 40s |
| `celery_beat` | 103-115 | Beat schedule heartbeat freshness | 30s | 60s |

The api healthcheck uses Python rather than `curl` because `curl` is not in the `python:3.11-slim` base image (finding D-M5 in the file's own comments). `restart: unless-stopped` (lines 66, 91, 121) provides crash recovery; healthcheck failure for `retries × interval` triggers automatic restart.

This was verified in the running stack — all five containers reported `(healthy)` after start.

**Action taken:** None.

**Client onboarding consequence:** Standard `docker compose up` brings the full stack up with health-gated dependencies. Crashed processes recover automatically through the combination of healthchecks and the restart policy.

---

### Finding 22 — Phantom npm package versions

**Evidence as reported**

> File: `package.json`
> `@types/node ^25.5.0` (latest 22.x), `@types/react ^19.2.14` and `@types/react-dom ^19.2.3` (react runtime is ^18.3.1), `vitest ^4.1.0` and `@vitest/*` (current 2.x), `terser ^5.46.0` (actual 5.36.x), `zustand ^5.0.12`. Phantom versions → npm fails or fetches typosquats.
> Remediation: Regenerate lockfile against a reviewed registry. Pin to real published versions only. Add `npm audit` to CI.

**Verdict: FALSE**

**Verification**

Live npm-registry check on 2026-05-01 confirms every cited version is real and current:

| Package | Manifest range | Installed | npm registry latest |
|---|---|---|---|
| `@types/node` | `^25.5.0` | 25.6.0 | 25.6.0 |
| `@types/react` | `^18.3.12` | 18.3.28 | 19.2.14 |
| `@types/react-dom` | `^18.3.1` | 18.3.7 | (current) |
| `vitest` | `^4.1.0` | 4.1.5 | 4.1.5 |
| `terser` | `^5.46.0` | 5.46.2 | 5.46.2 |
| `zustand` | `^5.0.12` | 5.0.12 | 5.0.12 |

The manifest pins `@types/react` to the 18.x line, deliberately matching the React 18.3.1 runtime — the manifest does not contain `@types/react ^19.2.14` as the report claims. The reviewer's stated "current" versions correspond to the npm registry as of approximately mid-2024 (Node 22 LTS era; vitest 2.x). All packages install successfully from the standard registry.

**Action taken:** None.

**Client onboarding consequence:** `npm install` resolves all dependencies from the public registry. The repository's `package-lock.json` is briefly out-of-sync with `package.json` and should be regenerated as routine maintenance (`rm package-lock.json && npm install && commit`); this is independent of any security finding.

---

### Finding 23 — Phantom PyJWT version

**Evidence as reported**

> File: `requirements.txt`
> Latest published is 2.9.0. Install either fails or pulls a typosquat (critical supply-chain risk).
> Remediation: Pin to an actually-published version (e.g., `pyjwt==2.9.0`).

**Verdict: FALSE**

**Verification**

`requirements.txt:30` pins `PyJWT==2.12.1`. PyPI (queried 2026-05-01) confirms `PyJWT 2.12.1` is the current latest release. The full available-versions list on PyPI:

```
2.12.1, 2.12.0, 2.11.0, 2.10.1, 2.10.0, 2.9.0, 2.8.0, 2.7.0, ...
```

Inside the running container:

```
PyJWT installed: 2.12.1
Name: PyJWT
Version: 2.12.1
```

The reviewer's stated "latest" of 2.9.0 corresponds to the PyPI snapshot from approximately July 2024. Downgrading to 2.9.0 would revert the CVE-2024-53861 fix (ID-token claim confusion) introduced in 2.10.0.

**Action taken:** None.

**Client onboarding consequence:** Production deployments should use the documented hash-verified install:

```bash
pip install --require-hashes -r requirements-locked.txt
```

(See `requirements.txt` lines 4-8.) This blocks any registry compromise — the package must hash-match the locked manifest, regardless of what is currently published.

---

## Summary table

| # | Finding | Verdict | Action |
|---|---|---|---|
| 1 | Refresh-token race / RFC 6819 | FALSE | None |
| 2 | OAuth tokens in redirect URL | FALSE | None |
| 3 | CSRF exempt /login /refresh | FALSE | None |
| 4 | `*.railway.app` CORS regex | FALSE | None |
| 5 | Hardcoded admin@tmalert.com MFA bypass | FALSE | None |
| 6 | Entra `tenant=common` permits any account | FALSE | None |
| 7 | Password-reset rate limit module-global | FALSE | None |
| 8 | `error_type` leak + DEBUG=true in prod | FALSE | None |
| 9 | TOTP QR via public service | FALSE | None |
| 10 | Tokens JS-accessible / Bearer interceptor | FALSE | None |
| 11 | Tokens in `/auth/callback` URL | FALSE | None |
| 12 | Prod CSP whitelists localhost / `https:` | PARTIAL | Removed meta-CSP from `index.html` |
| 13 | `console.log` URL with token in ResetPasswordPage | FALSE | None |
| 14 | Check-in token in respond endpoint query | FALSE | None |
| 15 | Backend on Railway (vendor infra) | OPERATIONAL | Templated `vercel.json`; created `vercel.json.example`; created `DEPLOYMENT.md` |
| 16 | Inline credentials in docker-compose | FALSE | None |
| 17 | Public Railway URL in repo | OPERATIONAL | Resolved via finding 15 |
| 18 | Frontend self-hosted deploy artefact missing | TRUE | Added `Dockerfile`, `nginx/default.conf.template`, `.dockerignore`, `DEPLOYMENT.md §3.5` |
| 19 | `proxy_pass localhost:8000` in nginx.conf | FALSE | None |
| 20 | `chmod 1777 /run/secrets` in Dockerfile | FALSE | None |
| 21 | App services missing healthchecks | FALSE | None |
| 22 | Phantom npm package versions | FALSE | None |
| 23 | Phantom PyJWT version | FALSE | None |

## Outstanding deliverables / how the client moves forward

The codebase is hosting-agnostic and compliance-aligned. To onboard a new deployment, the client performs the following in their environment, not in source:

1. **Choose a deployment topology.** Vercel + Railway, Vercel + on-prem, on-prem + on-prem, Kubernetes, etc. See `DEPLOYMENT.md §1` for the supported platform matrix and §3, §3.5, §5 for platform-specific instructions.
2. **Set deployment-specific environment variables.** See `DEPLOYMENT.md §2` (frontend) and §4 (backend). The backend refuses to start with an unsafe configuration (`app/config.py:_validate_auth_provider_safety`).
3. **Substitute the backend host in `vercel.json`** (or the platform equivalent — `_redirects`, `nginx.conf`, Ingress rule, etc.).
4. **First boot:** retrieve the bootstrap admin password from `/run/secrets/bootstrap_pw` inside the api container, log in, change the password, enrol MFA. Delete the bootstrap secret file. See `DEPLOYMENT.md §6`.
5. **Verification:** `DEPLOYMENT.md §7` lists the post-deploy checks (CSP, cookie attributes, CORS allow-list, healthchecks, `/health` reachability) the deploying organisation should run before announcing the deploy.

No source-code edits are required for any supported deployment topology. The single substantive code-side gap identified in this review (the absence of an on-prem frontend container artefact, finding 18) has been closed.
