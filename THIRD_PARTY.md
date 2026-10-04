# Third-party dependencies

ZentCal keeps runtime dependencies intentionally small.

## Go modules

- `github.com/jackc/pgx/v5` — PostgreSQL driver/pool — MIT License
- `golang.org/x/crypto` — bcrypt password hashing and PBKDF2 key derivation — BSD-3-Clause

No third-party JavaScript, CSS, font or icon library is loaded by the ZentCal web interface.

Docker base images used by the default build/runtime are the official Go, Alpine Linux and PostgreSQL images.
