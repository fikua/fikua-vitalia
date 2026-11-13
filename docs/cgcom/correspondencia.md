# Correspondencia con CGCOM

Resumen de lo acordado en cada correo. Los correos completos no se guardan aquí.

## 1. Pre-registro del cliente OIDC (login con DoctorID)

- Cliente `vitalia-authentik` en el tenant `cgcom`, entorno de desarrollo. Quien habla con el IdP de DoctorID es Authentik, el IdP de la clínica, que lo federa.
- Redirect URI: `https://vitalia-auth.fikua.com/source/oauth/callback/doctorid/`.
- Discovery: `https://cgcom.dev.eudistack.net/verifier/.well-known/openid-configuration`.
- El ID Token lleva el número de colegiado en `personal_administrative_number`, que también es el `sub`. No hace falta `userinfo`.
- `nonce` opcional; scopes `openid doctorid`; otros scopes conocidos se ignoran y los desconocidos dan error.
- Autenticación del cliente: primero `none`. Authentik no admite secreto vacío, así que CGCOM lo pasó a cliente confidencial con `client_secret_post`. El secreto llegó por un canal seguro y está solo en el `.env` del servidor.
- Logos: dos horizontales, para fondo blanco y fondo de color: `internal/web/static/logo-vitalia.svg` y `logo-vitalia-white.svg`.
- Estado: la petición de autorización llega al inicio de sesión de CGCOM. Falta un DoctorID real para probar la vuelta.

## 2. Vitalia como plataforma piloto del enrolamiento

- CGCOM propone que Vitalia sea la primera plataforma que se integra con el enrolamiento de médicos.
- Piden los datos de alta: ver [alta-plataforma.md](alta-plataforma.md).
- Entregan la credencial de plataforma (token por `private_key_jwt`, RFC 7523) y el secreto del webhook.
- API de desarrollo: `https://cgcom.dev.eudistack.net/cgcom-adapter`.
- Plazos por defecto: 7 días para que el médico obtenga su DoctorID y 30 minutos para confirmar sus datos.
- Por cerrar en su lado: colegiados de prueba, fecha de preproducción y formato del aviso del webhook (datos o solo referencia, y firma).

## 3. Credencial de plataforma, guía técnica y token

- Recibida la **credencial de plataforma** (LEARCredentialMachine, SD-JWT), atada a nuestra clave pública. Su `mandatee.id` es `did:key:zDnaemwTYeERGFiFZFgZzB3nPtPwUNF1tHunWiRQ8nkNTUmQo`, que coincide con el `did:key` calculado de nuestra clave (`internal/cgcom/didkey_test.go`). No es secreta, pero solo funciona con nuestra clave privada. Está en el `.env` del servidor (`VITALIA_CGCOM_CREDENTIAL`).
- Recibida la **guía técnica** (*Integrar tu plataforma con DoctorID*, v0.1.1, borrador).
- **Token**:
  - endpoint `https://cgcom.dev.eudistack.net/verifier/oidc/token`, grant `client_credentials` con `client_assertion` (RFC 7523);
  - en la aserción: `iss` = `sub` = `client_id` (el `did:key`), `aud` = `https://cgcom.dev.eudistack.net/verifier`, `jti` y caducidad de 120 s;
  - en el claim `vp_token`: el VP-JWT de la credencial en base64 estándar;
  - sin `scope`, con la cabecera `X-Tenant: cgcom`.

  Implementado tal como lo hace su SDK Java (código abierto).
- **Si no se confirma en 30 minutos**: el enrolamiento pasa a `EXPIRED`, llega un aviso y hay que enrolar de nuevo. El nuevo enrolamiento responde directamente `PENDING_CONFIRMATION`, sin que el médico vuelva al portal.
- **Secreto del webhook**: recibido por canal seguro. Guardado en el servidor (`VITALIA_CGCOM_WEBHOOK_SECRET`), aún no activo: el webhook sigue validando los avisos del simulador hasta que pasemos al servicio real.
- **Primera petición de token** (13-11-2026, 12:56:40 UTC, desde el servidor): `400 invalid_client`, sin descripción. El motivo: el Verifier espera la credencial como JWT W3C (VC 2.0), no como SD-JWT.

## 4. Credencial en formato JWT W3C

- CGCOM sustituye la credencial SD-JWT por una **JWT W3C** (modelo VC 2.0: el payload es la credencial, sin claim `vc`, con el mandato en `credentialSubject.mandate`). Misma clave y mismo `client_id`.
- En `vp.verifiableCredential` va el JWT tal cual, sin disclosures ni `~`. Nuestro código no necesitó cambios: ya mete la credencial tal cual y lee `cnf.jwk` de la raíz.
- **Token obtenido** (13-11-2026, 13:28:45 UTC): token de 15 minutos con `tenant: cgcom`, `scope: machine learcredential` y nuestro mandato (Clínica Vitalia, poder `Onboarding` en el dominio `cgcom`).
