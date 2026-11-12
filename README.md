# Clínica Vitalia

A **fictitious healthcare platform** used to test, end to end, how a real platform (a hospital group, an insurer) integrates with a DoctorID enrolment API: it enrols its physicians, receives the signed webhooks and confirms or rejects the physician's data.

All communication with the enrolment API is **server to server**. The small operator UI imitates a clinic's admissions back office. **Synthetic data only.**

Live at `https://vitalia.fikua.com` (test account, credentials are not in this repo).

## What it does

| Step | Operator UI | API call |
| --- | --- | --- |
| Register a physician | *Alta*: name, DNI/NIE/passport, 9-digit registration number | `POST /api/v1/enrollments` (`201` new, `200` existing open one) |
| Wait for the physician | Shows the issuance portal address to send | — |
| Receive notices | *Avisos recibidos* per physician | `POST /webhooks/enrollments` (signed, see below) |
| Review the DoctorID data | Our record next to the DoctorID data; confirm or reject | `POST …/{id}/confirmation` |
| Cancel | Button while the state allows it | `POST …/{id}/cancellation` |
| Refresh | *Consultar estado*: the GET is the source of truth | `GET …/{id}` |

The *Registro técnico* page lists every call (request, status, problem `type`, response, `Retry-After`) and every webhook received (raw body, signature result, processing outcome). It is the evidence of the integration.

### Webhook receiver

- `X-EUDIStack-Signature: t=<unix>,v1=<hex>`, `v1 = HMAC-SHA256(secret, "<t>.<raw body>")`. The signature is checked on the raw bytes before parsing, with a constant-time comparison. Several `v1` values are accepted, so the secret can be rotated.
- The timestamp must be within `VITALIA_SIGNATURE_TOLERANCE` (default 5 minutes) of the server clock, in either direction.
- A bad or missing signature gets `401`. The request is kept (truncated) for diagnosis and never processed.
- Deduplication is by `event_id`: a retry answers `200` with `"duplicate": true` and changes nothing.
- The receiver stores the event and answers right away. A background processor applies it afterwards. An event older than the stored state (by `updated_at`) is kept as `stale` and not applied. An event for an enrolment not known yet is kept and applied once that enrolment appears. When `VITALIA_REFRESH_ON_WEBHOOK=true`, each applied event triggers a GET.

## Layout

```
cmd/vitalia        the platform (UI + webhook + processor)
cmd/sendhook       sends a signed test webhook to a running instance
cmd/fakeadapter    in-memory API stand-in + /_sim page, for local demos
internal/adapter   API types and client (TokenSource: static token in phase 1)
internal/webhook   signature, receiver, sender
internal/enrollment  enrol / refresh / decide / cancel, webhook processor
internal/store     SQLite (modernc.org/sqlite, no cgo)
internal/web       operator UI (html/template, session login, cross-origin protection)
```

## Run locally

```sh
make demo          # platform on :8080 (admision / pruebas), simulator on :8090/_sim
make test vet
```

The simulator acts as the physician, the registry and the clock. Its scenarios depend on the registration number: one ending in `0` already has a DoctorID, one starting with `999` gets `503 issuer_unavailable`, and any other starts as `INITIATED`.

## Configuration

Environment variables, read once at startup; the process refuses to start if one is missing or invalid. See [`.env.example`](.env.example). No secret goes in this repo or in the logs (the token, the webhook secret and signatures are never logged).

## Deployment

The image is `fikua/vitalia`, built by [`release.yml`](.github/workflows/release.yml) on every push to `main`. It runs on the Fikua VPS behind Traefik and Cloudflare, with the configuration in `fikua-platform-iac/projects/vitalia/`. The host `.env` holds the secrets.

To check a deployment (TLS, routing, secret):

```sh
export VITALIA_WEBHOOK_SECRET=...   # same value as on the host
make sendhook     URL=https://vitalia.fikua.com/webhooks/enrollments   # expects 200
make sendhook-bad URL=https://vitalia.fikua.com/webhooks/enrollments   # expects 401
```

The VPS clock must be NTP-synchronised, because signatures are rejected beyond the tolerance window.

## License

MIT
