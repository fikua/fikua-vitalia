# Alta de Clínica Vitalia como plataforma de enrolamiento

Datos que CGCOM pide para dar de alta la plataforma. **Todo es ficticio**: Clínica Vitalia no existe como organización. Los datos están elegidos para que no coincidan con nadie real: un NIF de formato válido pero con todo ceros, y correos en el dominio reservado `.example`.

## Organización

| Dato | Valor |
| --- | --- |
| Denominación legal | Clínica Vitalia, S.L. (ficticia, entorno de pruebas) |
| NIF | B00000000 |
| País | España (ES) |

## Persona que firma el alta

| Dato | Valor |
| --- | --- |
| Nombre | Laura Fernández Soler |
| Cargo | Directora médica |
| Correo | direccion.medica@vitalia.example |
| Número de certificado | PRUEBAS-VITALIA-0001 |

El correo no recibe mensajes: `.example` es un dominio reservado. Las comunicaciones de CGCOM siguen llegando por el canal habitual del piloto.

## Servicio

| Dato | Valor |
| --- | --- |
| Dominio del servicio que llama a la API de enrolamiento | `https://vitalia.fikua.com` |
| Webhook (HTTPS) | `https://vitalia.fikua.com/webhooks/enrollments` |
| Plazo para que el médico obtenga su DoctorID | 7 días (por defecto) |
| Plazo para confirmar los datos | 30 minutos (por defecto) |

## Clave pública de plataforma (ES256, JWK)

```json
{"kty":"EC","crv":"P-256","x":"P5N-gnsH2OMBoNqb1ivU1Rd97ymRm9rDIBfLQH06Hcw","y":"fnEBrhXeCPRYGL6s-ksPhlEoNuckl35tV--VWl9m1P8"}
```

- Generada el 13-11-2026 con `cgcomkey`, en el propio servidor.
- La clave privada no ha salido de allí: está en el `.env` de `/opt/vps/projects/vitalia/` como `VITALIA_CGCOM_SIGNING_KEY`.
- El JWK lleva solo `kty`, `crv`, `x` e `y`, sin `d`.

Para rotarla: generar otro par con `cgcomkey`, enviar el nuevo JWK a CGCOM y sustituir `VITALIA_CGCOM_SIGNING_KEY` cuando lo confirmen.

## Lo que entrega CGCOM

| Dato | Dónde va | Estado |
| --- | --- | --- |
| Credencial de plataforma (LEARCredentialMachine, JWT W3C; sustituye a la SD-JWT) | `VITALIA_CGCOM_CREDENTIAL` | Recibida, en el servidor |
| `client_id`: el `did:key` de nuestra clave | Se calcula de la clave (`VITALIA_CGCOM_CLIENT_ID` vacío) | Comprobado |
| Token: `https://cgcom.dev.eudistack.net/verifier/oidc/token`, audiencia `https://cgcom.dev.eudistack.net/verifier`, tenant `cgcom` | `VITALIA_CGCOM_TOKEN_URL`, `_TOKEN_AUDIENCE`, `_TENANT` | Funciona: token obtenido el 13-11-2026 |
| Secreto del webhook | `VITALIA_CGCOM_WEBHOOK_SECRET`, que sustituirá a `VITALIA_WEBHOOK_SECRET` al pasar al servicio real | Recibido, en el servidor, sin activar |
| API (desarrollo) | `VITALIA_ADAPTER_BASE_URL=https://cgcom.dev.eudistack.net/cgcom-adapter` | Pendiente de preproducción |

## Médicos del piloto

Elegidos de la lista de colegiados de prueba de CGCOM para cubrir casos distintos. RRHH los dio de alta en Vitalia (`/gestion`) el 13-11-2026; Vitalia creó su usuario en Authentik y abrió su enrolamiento (por ahora contra el simulador).

| Colegiado | Médico | Documento | Qué probamos |
| --- | --- | --- | --- |
| 282812345 | María García López | 12345678Z (DNI) | Camino feliz |
| 464611111 | José Antonio García Fernández | 23456789D (DNI) | El certificado dice «PEPE»: discrepancia de identidad (`PENDING_AUTH_SOURCES`) |
| 303088888 | Andrei Popescu | X1234567L (NIE) | NIE, sin segundo apellido |
| 353510101 | Emma Schneider | PAA123456 (pasaporte) | Pasaporte |
| 181840404 | Antonio Moreno Jiménez | 22334455Y (DNI) | Baja colegial: el registro lo rechaza (`REJECTED_BY_REGISTRY`) |
