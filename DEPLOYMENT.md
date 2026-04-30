# Deployment Guide — Alert System

This guide explains how to deploy the alert system to *any* platform (Vercel, AWS,
Cloudflare, on-prem, etc.). Read it end-to-end before your first deploy.

---

## 1. Architecture contract (all platforms)

The frontend is a static SPA. It expects **`/api/*` to be a same-origin path that
proxies to the backend**. Every platform handles this differently:

| Platform | Mechanism |
|---|---|
| Vercel | `vercel.json` `rewrites` → `destination` |
| Cloudflare Pages | `_redirects` file |
| Netlify | `netlify.toml` `redirects` |
| AWS CloudFront | Origin behavior `/api/*` → backend origin |
| Nginx | `location /api/ { proxy_pass …; }` |
| Docker compose | The included `nginx.conf` is wired this way |

If you cannot use a same-origin proxy, see *§5 — Cross-origin deploys* for the
extra steps.

---

## 2. Frontend env vars (build time)

Set these in your hosting platform’s build settings (Vercel project → Settings →
Environment Variables, or the equivalent):

| Var | Value | Notes |
|---|---|---|
| `VITE_API_URL` | `/api/v1` | Relative path. The rewrite/proxy makes it same-origin. |

That is the only frontend build var. Do **not** set `VITE_API_URL` to an absolute
backend URL unless you’re intentionally doing a cross-origin deploy
(see §5) — doing so requires editing the CSP `connect-src` to allow that origin.

---

## 3. Vercel-specific deploy

The repo ships `alert-system-frontend/vercel.json` with a placeholder backend
host. **You must substitute it before a real deploy.** A clean template is
available at `alert-system-frontend/vercel.json.example`.

1. **Edit `alert-system-frontend/vercel.json` line 6** — replace
   `REPLACE_WITH_BACKEND_HOST` with your backend’s public hostname:

   ```json
   "destination": "https://YOUR-BACKEND.example.com/api/:path*"
   ```

   This is the **only** line you need to change in `vercel.json`. The CSP and
   security headers are already deployer-agnostic.

2. **Set `VITE_API_URL=/api/v1`** in the Vercel project’s environment variables
   for both *Production* and *Preview*.

3. Deploy.

`vercel.json` security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy,
Cache-Control) require no changes per deployer.

> **Note on hosting control plane**: routing the SPA through Vercel proxies all
> auth/MFA/PII traffic through Vercel’s edge to whatever backend host you
> name. If your compliance posture requires the data plane to run inside a
> controlled network (TM-managed Kubernetes, on-prem, etc.), serve the SPA
> from the same control plane (Cloudflare Tunnel + internal nginx,
> Kubernetes Ingress with a static-asset bucket, etc.) and skip Vercel
> entirely — `vercel.json` is purely Vercel-specific and is unused by other
> deploy targets. See §1 for the same-origin proxy contract on alternate
> platforms and §5 for cross-origin deployments.

---

## 3.5 On-prem / self-hosted frontend (Docker + nginx)

For TM-managed Kubernetes, on-prem nginx, or any non-Vercel target, build
the SPA into a container image. The repo ships a multi-stage `Dockerfile`
and an `nginx/default.conf.template` whose CSP and security headers
**mirror `vercel.json` exactly** — keep them in lockstep when changing.

### Build

```bash
cd alert-system-frontend
docker build -t alert-system-frontend:latest .
```

The default build assumes `VITE_API_URL=/api/v1` (relative). To point at
an absolute backend URL instead, pass it as a build-arg (cross-origin
deploys only — see §5):

```bash
docker build -t alert-system-frontend:latest \
  --build-arg VITE_API_URL=https://api.example.com/api/v1 .
```

### Run

The runtime container expects a `BACKEND_HOST` env var so its `/api/*`
proxy can find the backend service. The default is `api:8000` — works
unmodified inside a docker-compose network where the backend service is
named `api` on port 8000.

```bash
docker run -d \
  --name alert-frontend \
  --network tm-alert \
  -e BACKEND_HOST=tm-alert-api:8000 \
  -p 8080:8080 \
  alert-system-frontend:latest
```

| Setting | Default | Override when |
|---|---|---|
| Listen port | `8080` (unprivileged) | Map to `:80` / `:443` at the ingress |
| `BACKEND_HOST` | `api:8000` | Different service DNS / port |
| `NGINX_RESOLVER` | `127.0.0.11` (Docker embedded DNS) | Kubernetes (set to cluster DNS, e.g. `10.96.0.10`) or any host whose `/etc/resolv.conf` doesn’t point to the embedded resolver |
| User | `nginx` (non-root) | — |

### Kubernetes example

```yaml
env:
  - name: BACKEND_HOST
    value: alert-api.alerting.svc.cluster.local:8000
  - name: NGINX_RESOLVER
    value: kube-dns.kube-system.svc.cluster.local
ports:
  - containerPort: 8080
securityContext:
  runAsNonRoot: true
  runAsUser: 101    # nginx
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: false   # nginx needs to write /var/cache, /tmp
  capabilities:
    drop: ["ALL"]
```

### CSP & security headers — single source of truth

The on-prem nginx and the Vercel deploy share one CSP. Both sources are:

| File | Purpose |
|---|---|
| `alert-system-frontend/vercel.json` | Vercel response headers |
| `alert-system-frontend/nginx/default.conf.template` | nginx response headers (envsubst’d at startup) |
| `alert-system-frontend/vite.config.ts` | dev-server response headers (HMR-permissive) |

When you change CSP, change all three. There is no nonce machinery —
the production build emits zero inline scripts, so `script-src 'self'`
is sufficient and equivalent across hosting platforms.

---

## 4. Backend env vars (runtime)

The backend is a FastAPI app. It refuses to start with an unsafe configuration
(see `app/config.py:_validate_auth_provider_safety`). Set every var below before
your first deploy.

### Database & cache
| Var | Example | Required |
|---|---|---|
| `POSTGRES_USER` | `postgres` | Yes |
| `POSTGRES_PASSWORD` | strong random string | Yes |
| `POSTGRES_DB` | `tm_alert` | Yes |
| `DATABASE_URL` | `postgresql://USER:PASS@HOST:5432/tm_alert` | Yes |
| `REDIS_URL` | `redis://HOST:6379/0` | Yes |

### Identity & secrets
| Var | Notes |
|---|---|
| `SECRET_KEY` | 32+ random bytes; rotates invalidate all access tokens |
| `REFRESH_SECRET_KEY` | Independent of SECRET_KEY; rotation invalidates refresh tokens |
| `MFA_ENCRYPTION_KEY` | base64 Fernet key (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) |
| `MFA_CHALLENGE_SECRET_KEY` | hex random 64 chars |

### Origins & CORS
| Var | Example |
|---|---|
| `FRONTEND_URL` | `https://your-spa.example.com` |
| `BACKEND_URL` | `https://your-backend.example.com` |
| `APP_ENV` | `production` (anything other than literal `development` is treated as prod) |

### Auth providers
| Var | Required when |
|---|---|
| `AUTH_PROVIDERS` | always — comma list of `local,entra,ldap` |
| `ENTRA_ENABLED` | `true` to enable Microsoft SSO |
| `ENTRA_TENANT_ID` | **must** be a real GUID (never blank, never `common`) |
| `ENTRA_CLIENT_ID` | from Azure app registration |
| `ENTRA_CLIENT_SECRET` | from Azure app registration |
| `ENTRA_REDIRECT_URI` | `https://your-backend.example.com/api/v1/auth/entra/callback` |
| `LDAP_ENABLED` | `true` to enable LDAP |
| `LDAP_SERVER_URL`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_USER_SEARCH_BASE`, `LDAP_USER_SEARCH_FILTER`, `LDAP_EMAIL_ATTRIBUTE`, `LDAP_FIRST_NAME_ATTRIBUTE`, `LDAP_LAST_NAME_ATTRIBUTE`, `LDAP_USE_TLS` | required when LDAP enabled |

### Hard requirement when external SSO is on
If `ENTRA_ENABLED=true` *or* `LDAP_ENABLED=true`, you **must** also set:

```
ALLOWED_EMAIL_DOMAINS=your-company.com,subsidiary.com
```

Otherwise `_validate_auth_provider_safety()` raises and the container exits.
This guard prevents arbitrary Microsoft/LDAP identities from auto-provisioning
as Viewer accounts.

### External integrations (only if used)
| Var | Used by |
|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | SES email |
| `SES_FROM_EMAIL`, `SES_FROM_NAME` | SES email |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` | SMS |
| `LOCATIONIQ_API_KEY` | Geocoding |

---

## 5. Cross-origin deploys (frontend & backend on different origins)

If you cannot use a same-origin proxy and the SPA must call the backend
directly across origins, two things change:

1. **Frontend** — set `VITE_API_URL=https://your-backend.example.com/api/v1`
   (absolute URL).

2. **Frontend CSP** — edit `vercel.json` line 19 (or your platform’s
   equivalent header config) and add the backend origin to `connect-src`:

   ```
   connect-src 'self' https://your-backend.example.com
   ```

3. **Backend CORS** — set `FRONTEND_URL=https://your-spa.example.com` so the
   backend adds it to the CORS allow-list. The backend already trusts whatever
   you put here (no wildcards).

4. **Cookie SameSite** — `APP_ENV=production` automatically switches cookies
   to `SameSite=None; Secure`, which the browser requires for cross-site
   credentialed requests. Both origins must be HTTPS.

Same-origin proxy is the recommended pattern. Use it unless you have a hard
reason not to.

---

## 6. First boot

The backend seeds a default super-admin on first boot **only if no users
exist**:

```
email:    admin@tmalert.com
password: written to /run/secrets/bootstrap_pw inside the api container
```

Retrieve it with:

```bash
docker exec <api-container> cat /run/secrets/bootstrap_pw
```

The seeded user has `force_password_change=True` and `role=SUPER_ADMIN`.
Because SUPER_ADMIN is in `MFA_REQUIRED_ROLES`, the first login forces
both a password change and TOTP enrolment before any session is issued.

Delete the bootstrap secret file after the password is changed:

```bash
docker exec <api-container> rm /run/secrets/bootstrap_pw
```

---

## 7. Verification checklist (before announcing the deploy)

| Check | How |
|---|---|
| Backend starts without `_validate_auth_provider_safety` errors | `docker logs <api>` shows `Application startup complete` |
| Frontend loads | Open the SPA URL; no CSP violations in DevTools console |
| Login works | `admin@tmalert.com` + bootstrap password completes; TOTP enrolment shown |
| Cookies are HttpOnly + Secure | DevTools → Application → Cookies → all three (`access_token`, `refresh_token`, `csrf_token`) marked HttpOnly + Secure |
| `/health` returns 200 | `curl https://your-backend.example.com/health` |
| CORS only allows your frontend origin | `curl -H "Origin: https://attacker.test" https://your-backend.example.com/api/v1/auth/providers -i` should not echo `Access-Control-Allow-Origin: https://attacker.test` |

---

## 8. Operations notes

- **Rotating `SECRET_KEY` / `REFRESH_SECRET_KEY`** logs out every user.
  Communicate before rotation.
- **`AUTO_PROVISION_USERS=False`** if you want to disable JIT user creation
  on SSO and require an admin to invite each user manually.
- **`MFA_EXEMPT_EMAILS`** is honoured *only* when `APP_ENV=development`. It
  is hard-ignored in production. Do not rely on it for prod.
- **Postgres data volume** must be backed up — the `postgres_data` named
  volume in `docker-compose.yml` is your source of truth for users,
  notifications, and audit logs.
