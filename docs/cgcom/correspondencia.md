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
