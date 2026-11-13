# Esfuerzo de integración con el enrolamiento de CGCOM

Estimación del esfuerzo para que **una plataforma sanitaria que parte de cero** se integre con el enrolamiento de médicos de DoctorID, tomando Clínica Vitalia como caso piloto. Unidad: días de una persona desarrolladora.

Son estimaciones de lo que cuesta cada trabajo, no horas registradas. La columna *Estado* indica si en Vitalia ya está implementado y probado.

## Base de la estimación

- La plataforma ya tiene su ficha de médicos, su área de gestión y su inicio de sesión. Si no los tiene, quedan fuera de esta estimación.
- El inicio de sesión con DoctorID ya está integrado (OpenID Connect contra el IdP de CGCOM, directamente o a través del IdP de la plataforma).
- Lenguaje sin SDK de CGCOM (Vitalia está en Go). Con el SDK de Java, la parte del token baja a la mitad.

## Trabajos para integrarse

| # | Trabajo | Estimación | Estado en Vitalia |
| --- | --- | --- | --- |
| 1 | Cliente de la API de enrolamiento: alta, consulta, confirmación y cancelación; errores RFC 9457; reintentos con `Retry-After` | 2 | Implementado y probado |
| 2 | Receptor del webhook: firma HMAC sobre el cuerpo crudo, ventana de tiempo, deduplicación por `event_id`, avisos que llegan antes que la respuesta o desordenados | 1,5 | Implementado y probado |
| 3 | Estados del enrolamiento en la plataforma: ficha, pantallas de RRHH, revisión y confirmación de datos | 2 | Implementado y probado |
| 4 | Regla de acceso: solo médicos con enrolamiento completado y DoctorID vigente; bloqueo al recibir un aviso de invalidación | 1 | Implementado y probado |
| 5 | Credencial de plataforma: par ES256 y clave pública JWK (`kty`, `crv`, `x`, `y`) | 0,25 | Implementado y probado (`cgcomkey`) |
| 6 | Token de acceso por `private_key_jwt` (RFC 7523): aserción firmada, caché, renovación, reintento ante 401 | 1–1,5 | Implementado y probado; falta probarlo contra CGCOM |
| 7 | Organizar la integración en un módulo propio (`internal/cgcom`) | 0,5 | Hecho |
| 8 | Configuración y despliegue contra el entorno de CGCOM | 0,5 | Preparado; falta la credencial de CGCOM |
| 9 | Ajustes al contrato según la guía técnica | 0,5–1 | Pendiente de la guía |
| 10 | Pruebas de punta a punta y correcciones | 1–2 | Bloqueado: colegiados de prueba y preproducción |
| | **Total para integrarse** | **≈ 10–12** | |

## Trabajos que dependen de decisiones

| # | Trabajo | Estimación | Depende de |
| --- | --- | --- | --- |
| 11 | Cambio de formato del aviso (solo referencia, u otra firma como JWS) | 0–1,5 | CGCOM está decidiéndolo. Si solo trae la referencia, el coste es casi nulo: Vitalia ya consulta el enrolamiento tras cada aviso. |
| 12 | Confirmar los datos en 30 minutos | 0,5–1 | Decisión de producto: avisar a RRHH al momento, o confirmar automáticamente cuando los datos del registro coinciden con la ficha. |
| 13 | Avisar al médico con el enlace al portal de emisión | 0,5–1 | CGCOM no avisa al médico. Hoy RRHH ve el enlace y lo envía a mano; automatizarlo supone enviar correo. |
| 14 | Mantener el directorio de la plataforma (Authentik) al día con los médicos enrolados | ~1 | Para entrar con DoctorID a través de Authentik, el médico tiene que existir allí con su número de colegiado. |
| | **Total con todo** | **≈ 12–16** | |

## Lo que no es desarrollo pero bloquea

- Datos de alta de la organización y de quien firma: ver [alta-plataforma.md](alta-plataforma.md).
- Colegiados de prueba con certificado, que CGCOM está pidiendo.
- Conexión del entorno de preproducción de CGCOM.
- Guía técnica de la API y del token.
