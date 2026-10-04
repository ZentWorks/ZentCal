<p align="center">
  <img src="assets/ZentCal.png" alt="ZentCal logo" width="180">
</p>

<h1 align="center">ZentCal</h1>

<p align="center">A self-hosted calendar server for personal calendars, teams and shared company calendars.</p>

ZentCal combines CalDAV with a clean web interface for users, sharing, invitations, administration and backups.

## Features

- Personal, shared and centrally managed calendars
- Owner, contributor and viewer roles
- Normal and personal calendar modes — use Normal for a team calendar where members can work on shared events, or Personal when users should only manage the events they created themselves, for example a family or availability calendar.
- CalDAV support for Apple Calendar and other compatible clients
- App passwords for calendar clients
- Internal and external event invitations with RSVP handling
- SMTP notifications and customizable email templates
- OpenID Connect / OIDC single sign-on
- Audit history and event change history
- Webhooks, REST API and separate Admin API
- Encrypted local, S3-compatible and SFTP backups with restore support
- German and English web interface
- Dark mode and installable PWA
- No tracking, telemetry, CDN or external frontend assets

## Docker Compose

```yaml
services:
  init-secrets:
    image: alpine:3.24
    restart: "no"
    command:
      - /bin/sh
      - -ec
      - |
        umask 077
        mkdir -p /secrets
        if [ ! -s /secrets/postgres_password ]; then
          head -c 32 /dev/urandom | base64 | tr -d '\n' > /secrets/postgres_password
        fi
        chmod 0444 /secrets/postgres_password
        if [ ! -s /secrets/settings_key ]; then
          head -c 32 /dev/urandom | base64 | tr -d '\n' > /secrets/settings_key
        fi
        chmod 0444 /secrets/settings_key
    volumes:
      - zentcal-secrets:/secrets

  db:
    image: postgres:18.6-alpine
    restart: unless-stopped
    depends_on:
      init-secrets:
        condition: service_completed_successfully
    environment:
      POSTGRES_DB: zentcal
      POSTGRES_USER: zentcal
      POSTGRES_PASSWORD_FILE: /run/zentcal/postgres_password
    volumes:
      - zentcal-db:/var/lib/postgresql
      - zentcal-secrets:/run/zentcal:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U zentcal -d zentcal"]
      interval: 5s
      timeout: 3s
      retries: 20
    networks:
      - backend

  app:
    image: ghcr.io/zentworks/zentcal:latest
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
      init-secrets:
        condition: service_completed_successfully
    ports:
      - "8080:8080"
    environment:
      ZENTCAL_BASE_URL: "${ZENTCAL_BASE_URL:-http://localhost:8080}"
      ZENTCAL_DB_HOST: db
    volumes:
      - zentcal-secrets:/run/zentcal:ro
      - zentcal-data:/data
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - backend

volumes:
  zentcal-db:
  zentcal-secrets:
  zentcal-data:

networks:
  backend:
```

### Optional `.env`

ZentCal starts without a `.env` file. The default base URL is `http://localhost:8080`.

To set a public URL, copy the example and edit it:

```bash
cp .env.example .env
```

```env
ZENTCAL_BASE_URL=https://calendar.example.com
```

Start ZentCal:

```bash
docker compose up -d
```

Open `http://HOST:8080` and complete the first-run setup.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `ZENTCAL_BASE_URL` | `http://localhost:8080` | Canonical URL used for external links and OIDC redirects. Use the public HTTPS URL in production. |
| `ZENTCAL_ADDR` | `:8080` | Internal listen address. |
| `ZENTCAL_DB_HOST` | `db` | PostgreSQL host. |
| `ZENTCAL_DB_PORT` | `5432` | PostgreSQL port. |
| `ZENTCAL_DB_NAME` | `zentcal` | PostgreSQL database name. |
| `ZENTCAL_DB_USER` | `zentcal` | PostgreSQL user. |
| `ZENTCAL_DB_PASSWORD_FILE` | `/run/zentcal/postgres_password` | File containing the PostgreSQL password. |
| `ZENTCAL_SETTINGS_KEY_FILE` | `/run/zentcal/settings_key` | File containing the key used to encrypt sensitive settings. |

Most application settings, including timezone, SMTP, SSO, backup targets and webhooks, are configured in the ZentCal web interface.

## Reverse proxy

ZentCal works behind nginx, Caddy, Traefik, HAProxy or another reverse proxy. Use HTTPS and set `ZENTCAL_BASE_URL` to the public URL, for example `https://calendar.example.com`.

## Build from source

```bash
docker build -t zentcal:local .
```

Or use Go directly:

```bash
go build -o zentcal ./cmd/zentcal
```

## Security

Use HTTPS for public deployments and keep the PostgreSQL service private. CalDAV clients authenticate with personal app passwords instead of account or SSO passwords.

See [SECURITY.md](SECURITY.md) for security details and vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
