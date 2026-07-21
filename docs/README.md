# NetWatch Documentation

Everything you need to understand, set up, operate, and extend NetWatch.

## Core

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, event bus, intelligence layer, threading, schema |
| [API_REFERENCE.md](API_REFERENCE.md) | Every REST endpoint and the SSE stream, with examples |
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | Step-by-step installation for all platforms |
| [USER_MANUAL.md](USER_MANUAL.md) | How to use the dashboard, page by page |
| [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) | Services, reverse proxy, security, backups |
| [SECURITY.md](SECURITY.md) | Threat model, authentication, hardening |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and platform-specific fixes |

## Capture setup

Getting NetWatch to actually *see* the traffic you care about depends on how
the monitoring host is wired in. These cover the harder cases:

| Document | Description |
|----------|-------------|
| [PORT_MIRROR_SETUP.md](PORT_MIRROR_SETUP.md) | Configuring a SPAN/mirror port for full-segment visibility |
| [ETHERNET_CABLE_GUIDE.md](ETHERNET_CABLE_GUIDE.md) | Wired host, client, and direct-link setups |
| [IDLE_CLIENT_BASELINE.md](IDLE_CLIENT_BASELINE.md) | What a genuinely idle client should look like, and how it's validated |

## Operations

| Document | Description |
|----------|-------------|
| [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) | Running a live demo, including preflight checks |

## Quick Links

- **New to NetWatch?** Start with [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Want to understand how it works?** Read [ARCHITECTURE.md](ARCHITECTURE.md)
- **Curious about the AI parts?** See *Intelligence Layer* in [ARCHITECTURE.md](ARCHITECTURE.md) and the AI endpoints in [API_REFERENCE.md](API_REFERENCE.md)
- **Building against the API?** Check [API_REFERENCE.md](API_REFERENCE.md)
- **Using the dashboard?** See [USER_MANUAL.md](USER_MANUAL.md)
- **Seeing no devices / no traffic?** [TROUBLESHOOTING.md](TROUBLESHOOTING.md), then [PORT_MIRROR_SETUP.md](PORT_MIRROR_SETUP.md)
- **Deploying to production?** Follow [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) and [SECURITY.md](SECURITY.md)
- **Contributing code?** See [CONTRIBUTING.md](../CONTRIBUTING.md) in the project root

## Getting Help

1. Check the relevant document above
2. Review [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
3. Open an issue on the project repository
