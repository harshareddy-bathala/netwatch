# NetWatch Security Guide

## Table of Contents

1. [API Authentication](#api-authentication)
2. [Transport Security (HTTPS)](#transport-security-https)
3. [Content Security Policy](#content-security-policy)
4. [Rate Limiting](#rate-limiting)
5. [Reverse Proxy Hardening](#reverse-proxy-hardening)
6. [Windows Defender Exclusions](#windows-defender-exclusions)
7. [Security Checklist](#security-checklist)
8. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## API Authentication

NetWatch protects all `/api/*` endpoints with API key authentication
when running in **production** mode (`NETWATCH_ENV=production`).

### Setting an API Key

```bash
# Generate a strong key
export NETWATCH_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
```

### Using the API Key

**Header (preferred for programmatic access):**
```bash
curl -H "X-API-Key: YOUR_KEY" http://localhost:5000/api/status
```

**Bearer token:**
```bash
curl -H "Authorization: Bearer YOUR_KEY" http://localhost:5000/api/status
```

**Query parameter (for SSE / EventSource — cannot send custom headers):**
```javascript
const es = new EventSource('/api/stream?api_key=YOUR_KEY');
```

### Auth-Exempt Routes

The following routes bypass authentication for operational reasons:

| Route | Reason |
|-------|--------|
| `/health` | Load-balancer health checks |
| `/` | SPA entry point |
| `/api/status` | Basic status (version stripped when unauthenticated) |
| `/api/info` | App metadata |

> **Note:** `/api/stream` requires authentication in production.
> Pass the API key via `?api_key=` since EventSource cannot send headers.

---

## Transport Security (HTTPS)

NetWatch itself binds to `127.0.0.1:5000` and communicates over plain
HTTP. HTTPS termination is handled by a reverse proxy (Nginx, Caddy, etc.).

### HSTS

When the reverse proxy sets `X-Forwarded-Proto: https`, NetWatch
automatically adds the HSTS header:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Setting Up HTTPS

See [deploy/nginx.conf.example](../deploy/nginx.conf.example) for a
complete Nginx configuration with:

- TLS 1.2+ only
- Strong cipher suite
- HTTP → HTTPS redirect
- SSE proxy settings (buffering disabled)
- Static asset caching (30 days)

---

## Content Security Policy

NetWatch sets the following CSP header on every response:

```
default-src 'self';
script-src 'self' https://cdn.jsdelivr.net;
style-src 'self' https://fonts.googleapis.com;
img-src 'self' data:;
connect-src 'self';
font-src 'self' https://fonts.gstatic.com
```

- **No `unsafe-inline`** — all scripts and styles are external files.
- CDN access is restricted to `cdn.jsdelivr.net` (Chart.js) and
  Google Fonts.

---

## Rate Limiting

Enabled automatically in production:

| Setting | Default |
|---------|---------|
| Requests/minute/IP | 100 |
| Requests/hour/IP | 2 000 |
| Localhost bypass | Yes |
| Window type | Sliding window (in-memory) |

Response headers:
- `X-RateLimit-Limit` — max requests per minute
- `X-RateLimit-Remaining` — requests left in current minute window
- `X-RateLimit-Limit-Hour` — max requests per hour

Exceeding either limit returns `429 Too Many Requests` with a `retry_after` hint.

---

## Reverse Proxy Hardening

### Nginx

A production-ready config is at [deploy/nginx.conf.example](../deploy/nginx.conf.example).

Key settings:
- Proxy `X-Forwarded-Proto` so HSTS activates
- Disable proxy buffering for `/api/stream` (SSE)
- Set `proxy_read_timeout 86400s` for long-lived SSE connections
- Cache static assets with `expires 30d`

### Caddy (alternative)

```caddyfile
netwatch.example.com {
    reverse_proxy 127.0.0.1:5000
    header /api/stream {
        -X-Accel-Buffering
    }
}
```

---

## Windows Defender Exclusions

Npcap's raw socket capture and NetWatch's packet processing can trigger
false positives in Windows Defender. Add these exclusions:

### Via PowerShell (Run as Administrator)

```powershell
# Exclude NetWatch directory
Add-MpPreference -ExclusionPath "C:\NetWatch"

# Exclude the Python process
Add-MpPreference -ExclusionProcess "C:\NetWatch\venv\Scripts\python.exe"

# Exclude Npcap driver
Add-MpPreference -ExclusionPath "C:\Windows\System32\Npcap"
```

### Via Settings UI

1. **Windows Security** → **Virus & threat protection** → **Manage settings**
2. Scroll to **Exclusions** → **Add or remove exclusions**
3. Add folder: `C:\NetWatch`
4. Add process: `python.exe`

### Why Exclusions Are Needed

| Activity | Defender concern |
|----------|-----------------|
| Raw socket capture (Npcap) | Flagged as potentially unwanted network activity |
| High packet rates | Real-time protection scans each file I/O |
| Database writes | WAL journal files trigger repeated scans |

> **Important:** Only exclude the NetWatch-specific paths.
> Do not broadly exclude Python or system directories.

---

## Security Checklist

### Before Deployment

- [ ] `NETWATCH_ENV=production` is set
- [ ] `SECRET_KEY` is a strong random value (≥ 32 bytes)
- [ ] `NETWATCH_API_KEY` is set for all API consumers
- [ ] Flask binds to `127.0.0.1` only (default)
- [ ] Reverse proxy terminates HTTPS
- [ ] HSTS verified (check `X-Forwarded-Proto` header)
- [ ] Firewall blocks direct access to port 5000
- [ ] Database directory has restrictive permissions (`chmod 750`)

### Periodic Review

- [ ] Rotate API keys quarterly
- [ ] Review access logs for unauthorized attempts
- [ ] Update dependencies (`pip list --outdated`)
- [ ] Run security scan (`pip-audit` or `safety check`)
- [ ] Verify CSP headers with browser DevTools

---

## Reporting Vulnerabilities

If you discover a security issue in NetWatch, please report it
responsibly:

1. **Do not** open a public GitHub issue
2. Email security findings to the maintainers
3. Include steps to reproduce and potential impact
4. Allow 90 days for a fix before public disclosure

We appreciate responsible disclosure and will credit reporters
in the release notes (with permission).
