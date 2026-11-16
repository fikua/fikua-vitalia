# Clínica Vitalia

A **fictitious clinic** used to test, end to end, how a real healthcare organisation integrates with DoctorID. The clinic has its own physicians and wants them to sign in to its systems with their DoctorID:

1. **Enrolment.** HR registers each physician and enrols them through the enrolment API, server to server. When the physician has a DoctorID, HR reviews the registry data and confirms it.
2. **Sign-in.** Physicians enter the professional area with **"Acceder con DoctorID"**. The clinic is an OpenID Connect client of the DoctorID identity provider (Authorization Code Flow, PKCE S256, `private_key_jwt`). Access is granted when the registration number in the ID Token belongs to a physician whose enrolment is `COMPLETED` and whose DoctorID is not revoked.

**Synthetic data only.** Live at `https://vitalia.fikua.com` (test accounts, credentials are not in this repo).

## Areas

| Path | Who | What |
| --- | --- | --- |
| `/` | Anyone | The clinic's public website. |
| `/profesional` | Physicians | Sign in with DoctorID; their space (agenda, verified identity). |
| `/gestion` | HR (username and password) | Register physicians, enrolment, data review, technical log. |
| `/webhooks/enrollments` | Enrolment API | Signed notifications (server to server). |
| `/.well-known/jwks.json` | Identity provider | Public key of the clinic's client assertions. |

## Enrolment (server to server)

| Step | Management UI | API call |
| --- | --- | --- |
| Register a physician | *Alta*: name, DNI/NIE/passport, 9-digit registration number | `POST /api/v1/enrollments` (`201` new, `200` existing open one) |
| Wait for the physician | Shows the issuance portal address to send | — |
| Receive notices | Activity per physician | `POST /webhooks/enrollments` (signed, see below) |
| Review the DoctorID data | Our record next to the DoctorID data; confirm or reject | `POST …/{id}/confirmation` |
| Cancel / refresh | Buttons; the GET is the source of truth | `POST …/{id}/cancellation`, `GET …/{id}` |

### Webhook receiver

- `X-EUDIStack-Signature: t=<unix>,v1=<hex>`, `v1 = HMAC-SHA256(secret, "<t>.<raw body>")`. The signature is checked on the raw bytes before parsing, with a constant-time comparison. Several `v1` values are accepted, so the secret can be rotated.
- The timestamp must be within `VITALIA_SIGNATURE_TOLERANCE` (default 5 minutes) of the server clock, in either direction.
- A bad or missing signature gets `401`. The request is kept (truncated) for diagnosis and never processed.
- Deduplication is by `event_id`. The receiver stores the event and answers right away, and a background processor applies it afterwards.
- An event older than the stored state (by `updated_at`) is not applied. An event for an enrolment not known yet waits until that enrolment appears.

## Sign-in with DoctorID (OIDC)

- Redirect to the identity provider with `state`, `nonce` and a PKCE S256 challenge. The `state` is bound to the browser with a cookie.
- On the callback, the clinic checks `state`, rejects an `iss` (RFC 9207) that is not its issuer, and redeems the code with a `private_key_jwt` assertion (ES256, audience the token endpoint). It then verifies the ID Token (signature, `iss`, `aud`, expiry, `nonce`).
- The access rule reads `personal_administrative_number`, which holds the registration number in DoctorID v1:
  - no physician with that number: `not_registered`;
  - the enrolment is not `COMPLETED`: `not_verified`;
  - the DoctorID was revoked or is being renewed: `doctorid_invalidated`.
- The first sign-in binds the DoctorID identity (`iss`, `sub`) to the physician's record, and later sign-ins must present the same one. HR can unbind it.
- Every attempt is logged with its outcome and the ID Token claims.

## Layout

```
cmd/vitalia          the clinic
cmd/sendhook         sends a signed test webhook to a running instance
cmd/cgcomkey         generates the CGCOM platform key; prints the public JWK
cmd/fakeadapter      stand-ins of the enrolment API (REST and SCIM 2.0) and the identity provider, plus /_sim
deploy/authentik     Authentik for the clinic: compose file and blueprint
internal/cgcom       CGCOM integration: enrolment API client and types, platform key (ES256 JWK),
                     API token by private_key_jwt, webhook signature
internal/webhook     the clinic's webhook receiver (stores signed events)
internal/enrollment  enrol / refresh / decide / cancel, webhook processor
internal/doctorlogin OIDC relying party and the access rule
internal/idpstub     simulated OpenID Provider (tests and demos)
internal/store       PostgreSQL (pgx), embedded migrations; cmd/sqlite2pg is the one-off copy from the old SQLite
internal/web         website, professional area, management area
```

## Run locally

```sh
make demo          # clinic on :8080 (HR: rrhh / pruebas), simulators on :8090 and :8091
make test vet
```

In `/_sim` (http://localhost:8091/_sim) you act as the physician, the registry and the clock:

- **obtain** issues the DoctorID, with the registry name you type.
- Then sign in at http://localhost:8080/profesional. The simulated IdP lets you pick which DoctorID to present, including an outsider to test the refusal.

Scenarios depend on the registration number: one ending in `0` already has a DoctorID, and one starting with `999` gets `503 issuer_unavailable`.

## The clinic with its own directory (Authentik)

The clinic can also keep its staff and physicians in [Authentik](https://goauthentik.io) (2026.8), as a real organisation keeps them in Entra ID or Okta. Everything on the Authentik side is configuration, in [`deploy/authentik/blueprints/vitalia.yaml`](deploy/authentik/blueprints/vitalia.yaml):

| What | How |
| --- | --- |
| Directory | Group `Vitalia RRHH` (account `rrhh`) and group `Vitalia Médicos` (five synthetic physicians). A physician's username is their registration number. Their attributes hold `collegiate_number` and `administrative_number`. |
| Enrolment by SCIM 2.0 | A SCIM provider sends the `Vitalia Médicos` group to the enrolment service. A property mapping adds the extension `urn:eudistack:params:scim:schemas:extension:doctorid:1.0:User` (`collegiateNumber`, `administrativeNumber`). An organisation that keeps those values elsewhere changes the mapping, not code. |
| DoctorID federation | The DoctorID identity provider (CGCOM Verifier) is an OIDC source with a **DoctorID** button on the login page. The sign-in is linked to the account whose username is the presented `personal_administrative_number`. There is no enrolment flow, so a DoctorID from outside the clinic is refused by Authentik. |
| Vitalia | OIDC client with a client secret. HR signs in to `/gestion` with their account, and the token must list `Vitalia RRHH`. Physicians sign in to `/profesional` through Authentik and DoctorID. A `doctorid` scope puts the registration number in `personal_administrative_number`, so the clinic's access rule is unchanged. |

The SCIM front of the enrolment service is a **proposal**, simulated in `fakeadapter` (`/scim/v2`):

- creating a user enrols the physician;
- `active=false` or `DELETE` cancels the open enrolment;
- reactivating, or changing the identifiers, opens a new enrolment;
- each enrolment opened or cancelled this way is notified with the usual signed webhook.

The clinic did not open those enrolments, so it adopts them by registration number. If an event's enrolment is still unknown after 15 seconds, the clinic attaches it to the physician with that number, or creates the physician if there is none.

```sh
make authentik-env     # once: deploy/authentik/.env with random secrets (admin and HR passwords in it)
make demo-authentik    # terminal 1: simulators + Vitalia wired to Authentik
make authentik-up      # terminal 2: Authentik on http://localhost:9000
```

Start `demo-authentik` first: Authentik reads the DoctorID JWKS from the simulator when it applies the blueprint. The physicians are provisioned on the first SCIM sync, and the simulator's `/_sim` lists them. Locally, Authentik reaches the simulators through `host.docker.internal`, while the browser uses `localhost`.

## Configuration

Environment variables, read once at startup; the process refuses to start if one is missing or invalid. See [`.env.example`](.env.example). No secret goes in this repo or in the logs.

Telemetry and audit follow the Fikua observability convention (fikua-docs `conv-observability.md`): with `OTEL_EXPORTER_OTLP_ENDPOINT` set, both binaries (`vitalia`, `fakeadapter` as `vitalia-sim`) send traces, metrics and logs to the platform Collector; without it, logs only go to stdout. Set `OTEL_RESOURCE_ATTRIBUTES=service.namespace=vitalia,deployment.environment=prd`. The audit catalogue (registrations, enrolment decisions, sign-ins, refusals; internal identifiers only) is in [`internal/audit`](internal/audit/audit.go), and every operation is counted in `vitalia.business.operations`.

## Deployment

The image is `fikua/vitalia`, built by [`release.yml`](.github/workflows/release.yml) on every push to `main`. It runs on the Fikua VPS behind Traefik and Cloudflare, with the configuration in `fikua-platform-iac/projects/vitalia/`. In phase 1 the simulators run next to it; the simulated identity provider is at `vitalia-idp.fikua.com`.

To check a deployment (TLS, routing, secret):

```sh
export VITALIA_WEBHOOK_SECRET=...   # same value as on the host
make sendhook     URL=https://vitalia.fikua.com/webhooks/enrollments   # expects 200
make sendhook-bad URL=https://vitalia.fikua.com/webhooks/enrollments   # expects 401
```

## License

MIT
