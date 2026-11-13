# Integración con CGCOM (DoctorID)

Clínica Vitalia es una **clínica ficticia** que hace de plataforma piloto en la integración con el enrolamiento de médicos de DoctorID del Consejo General de Colegios Oficiales de Médicos (CGCOM). Todos los datos de la organización, de las personas y de los médicos son **sintéticos**.

| Documento | Contenido |
| --- | --- |
| [alta-plataforma.md](alta-plataforma.md) | Datos de alta de la plataforma que pide CGCOM (ficticios) y la clave pública. |
| [esfuerzo-integracion.md](esfuerzo-integracion.md) | Qué supone integrarse para una plataforma que parte de cero: trabajos, estimación y estado. |
| [correspondencia.md](correspondencia.md) | Resumen de los correos con CGCOM y lo acordado en cada uno. |

El código de la integración está en [`internal/cgcom`](../../internal/cgcom) y la clave se genera con [`cmd/cgcomkey`](../../cmd/cgcomkey).
