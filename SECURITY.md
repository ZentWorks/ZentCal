# Security

## Reporting a vulnerability

Please do not publish exploitable security issues in a public GitHub issue.

Until a dedicated security contact is published, use GitHub's private vulnerability reporting for this repository when available. Include the affected version, reproduction steps, impact and any relevant logs with secrets removed.

## Security model

- CalDAV/WebDAV accepts **app passwords only**. The normal ZentCal account password and SSO credentials are never valid DAV credentials.
- API write operations require API bearer tokens with the required scope. Browser session cookies are read-only credentials for `/api/v1`.
- Passwords are hashed with bcrypt. API tokens and app passwords are stored as hashes; app passwords additionally keep the HTTP Digest verifier required for DAV Digest authentication.
- Integration secrets are encrypted at rest with the persistent ZentCal settings key.
- PostgreSQL is not exposed by the default Docker Compose stack.
- The default application container runs as a non-root user with dropped Linux capabilities, `no-new-privileges` and a read-only root filesystem.
- ZentCal does not trust forwarded scheme headers by default. ZentCal does not derive security-sensitive external links from forwarded or Host headers. Configure the canonical public URL with `ZENTCAL_BASE_URL`.

## Deployment recommendations

- Put production instances behind HTTPS.
- Set `ZENTCAL_BASE_URL` to the public HTTPS URL before enabling OIDC or sending invitations externally.
- Keep Docker, the reverse proxy and the ZentCal image updated.
- Keep the `zentcal-secrets`, database and backup volumes private.
- Use unique app passwords per device and revoke unused credentials.
- Verify backups regularly and retain the backup encryption password outside the backup archive.
