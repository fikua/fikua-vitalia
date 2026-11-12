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
cmd/fakeadapter      stand-ins of the enrolment API and the identity provider, plus /_sim
internal/adapter     enrolment API types and client (TokenSource: static token in phase 1)
internal/webhook     signature, receiver, sender
internal/enrollment  enrol / refresh / decide / cancel, webhook processor
internal/doctorlogin OIDC relying party and the access rule
internal/idpstub     simulated OpenID Provider (tests and demos)
internal/store       SQLite (modernc.org/sqlite, no cgo)
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

## Configuration

Environment variables, read once at startup; the process refuses to start if one is missing or invalid. See [`.env.example`](.env.example). No secret goes in this repo or in the logs.

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
