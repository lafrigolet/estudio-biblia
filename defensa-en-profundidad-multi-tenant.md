# Autenticación web: de sesiones clásicas a JWT con refresh tokens

> Documento didáctico que recorre la evolución de los mecanismos de autenticación en la web, mostrando cómo cada solución surge para resolver los problemas de la anterior.

---

## Índice

1. [Introducción: el problema de la identificación](#1-introducción-el-problema-de-la-identificación)
2. [Sesiones clásicas (server-side sessions)](#2-sesiones-clásicas-server-side-sessions)
3. [JWT: la respuesta stateless](#3-jwt-la-respuesta-stateless)
4. [El problema de los JWT y el refresh token](#4-el-problema-de-los-jwt-y-el-refresh-token)
5. [Flujo de expiración del access token](#5-flujo-de-expiración-del-access-token)
6. [¿Y si roban ambos tokens?](#6-y-si-roban-ambos-tokens)
7. [¿Cuál es entonces el sentido del refresh token?](#7-cuál-es-entonces-el-sentido-del-refresh-token)
8. [Comparación final y cuándo elegir cada modelo](#8-comparación-final-y-cuándo-elegir-cada-modelo)

---

## 1. Introducción: el problema de la identificación

HTTP es un protocolo **sin estado**. Cada petición es independiente: el servidor, por defecto, no tiene forma de saber si dos peticiones consecutivas vienen del mismo usuario. Esto era suficiente para la web original (servir documentos estáticos), pero deja de serlo en cuanto necesitas:

- Que un usuario haga login una vez y siga autenticado durante la navegación.
- Distinguir qué usuario hace cada acción.
- Mantener un carrito, preferencias, permisos.

El problema fundamental se reduce a una pregunta:

> **¿Cómo demuestra un cliente, en cada petición, que es quien dice ser, sin tener que mandar la contraseña cada vez?**

La respuesta general siempre es la misma: **emitir un credencial temporal** después del login, que el cliente envía en cada petición posterior. La diferencia entre los modelos que veremos está en **qué contiene ese credencial** y **dónde vive la información de identidad**:

| Modelo | Dónde vive la identidad | Qué lleva el cliente |
|---|---|---|
| Sesión clásica | En el servidor | Un identificador opaco |
| JWT | En el propio token | Un token autocontenido y firmado |
| JWT + refresh | Igual que JWT, pero con renovación | Dos tokens con perfiles distintos |

Entender por qué cada modelo existe es entender qué problema del anterior intenta resolver. Eso es lo que vamos a recorrer.

---

## 2. Sesiones clásicas (server-side sessions)

### La idea central

> El servidor recuerda quién eres. El cliente solo lleva un **identificador opaco** que apunta a esa memoria.

El identificador es un string aleatorio largo (ej. `s:8f4j2k9d1m...`), sin ningún significado por sí mismo. Si lo decodificas, no obtienes nada — es solo una **clave** para buscar en una tabla del servidor.

```
Cliente:  "Hola, soy la sesión abc123"
Servidor: [busca abc123 en su almacén] → "Ah, eres Ana, tenant X, rol admin"
```

### Flujo paso a paso

```
┌──────────┐                                       ┌──────────┐         ┌────────┐
│ Cliente  │                                       │ Servidor │         │  Store │
└────┬─────┘                                       └────┬─────┘         └───┬────┘
     │                                                  │                   │
     │ 1. POST /login (usuario + contraseña)            │                   │
     ├─────────────────────────────────────────────────►│                   │
     │                                                  │                   │
     │                                                  │ 2. Valida creds   │
     │                                                  │    Genera ID      │
     │                                                  │    aleatorio      │
     │                                                  │    "abc123"       │
     │                                                  │                   │
     │                                                  │ 3. Guarda sesión  │
     │                                                  ├──────────────────►│
     │                                                  │   abc123 → {      │
     │                                                  │     userId: 42,   │
     │                                                  │     tenantId: ..  │
     │                                                  │     expiresAt: .. │
     │                                                  │   }               │
     │                                                  │                   │
     │ 4. 200 OK                                        │                   │
     │    Set-Cookie: sid=abc123;                       │                   │
     │      HttpOnly; Secure; SameSite=Lax              │                   │
     │◄─────────────────────────────────────────────────┤                   │
     │                                                  │                   │
     │ 5. GET /api/datos                                │                   │
     │    Cookie: sid=abc123                            │                   │
     ├─────────────────────────────────────────────────►│                   │
     │                                                  │                   │
     │                                                  │ 6. Lee cookie     │
     │                                                  │    Busca sesión   │
     │                                                  ├──────────────────►│
     │                                                  │◄──────────────────┤
     │                                                  │   { userId: 42 }  │
     │                                                  │                   │
     │ 7. 200 OK { data }                               │                   │
     │◄─────────────────────────────────────────────────┤                   │
     │                                                  │                   │
     │             ... usuario hace logout ...          │                   │
     │                                                  │                   │
     │ 8. POST /logout                                  │                   │
     ├─────────────────────────────────────────────────►│                   │
     │                                                  │ 9. DELETE abc123  │
     │                                                  ├──────────────────►│
     │ 10. 200 OK + borrar cookie                       │                   │
     │◄─────────────────────────────────────────────────┤                   │
```

Lo crítico: **el servidor toca el almacén en cada petición autenticada** (paso 6). Eso es a la vez la fuerza y la debilidad del modelo.

### Dónde se guarda la sesión

- **Memoria del proceso**: solo válido si tienes un único servidor. Para algo serio, no.
- **Base de datos relacional**: persistente y auditable, pero más lento.
- **Redis o similar**: en memoria, rápido, soporta TTL nativo, comparte estado entre instancias. **Es el estándar de facto** hoy.

### La cookie: el detalle que mucha gente ignora

El identificador viaja en una cookie. Las flags de configuración de las cookies importan **mucho**:

| Flag | Qué hace | Por qué importa |
|---|---|---|
| `HttpOnly` | El JavaScript no puede leerla | Bloquea robo vía XSS |
| `Secure` | Solo viaja por HTTPS | Bloquea robo vía red |
| `SameSite=Lax` o `Strict` | Limita envío cross-site | Mitiga CSRF |
| `Domain` y `Path` | Limita el alcance | Reduce superficie de ataque |
| `Max-Age` / `Expires` | Cuándo el navegador la borra | Controla persistencia |

Una sesión bien configurada con estas flags es **más segura por defecto** que un JWT en `localStorage`.

### Problemas asociados a las sesiones clásicas

#### 1. Escalabilidad horizontal

Si la sesión vive en la memoria del servidor A, y el siguiente request lo atiende el servidor B (load balancer), B no encuentra la sesión.

- **Sticky sessions**: el LB manda siempre al mismo servidor. Funciona pero es frágil.
- **Almacén compartido** (Redis): todos los servidores leen del mismo sitio. Solución correcta hoy.

> No es un problema *real* en 2025, pero históricamente fue **el** argumento que impulsó JWT.

#### 2. Latencia y carga del store

Cada petición autenticada = una lectura al almacén. Con Redis es ~1ms, pero:

- Si el store cae, **toda la app cae**.
- En picos de tráfico, el store puede saturarse antes que la app.
- Si tu app tiene 50 microservicios y cada uno valida la sesión, son 50 lecturas a Redis por request.

#### 3. CSRF (Cross-Site Request Forgery)

**El gran problema histórico de las sesiones con cookies.** El navegador envía cookies **automáticamente** al dominio que las emitió. Si estás logueado en `tubanco.com` y visitas `evil.com`:

```html
<form action="https://tubanco.com/transferir" method="POST">
  <input name="destino" value="atacante">
  <input name="cantidad" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

El navegador envía la cookie de sesión sin que tú lo autorices.

**Defensas:**
- `SameSite=Lax` o `Strict` → mata el 95% de CSRF y hoy es el default.
- **Tokens CSRF** sincronizados.
- **Verificar `Origin` / `Referer`** en endpoints sensibles.

#### 4. CORS y subdominios

Las cookies tienen reglas de dominio rígidas. Para un SaaS multi-tenant con dominios custom (como SplitPay), las cookies third-party están cada vez más restringidas (Safari ITP, Chrome bloqueando 3rd party cookies). **Complica seriamente** el modelo.

#### 5. Mobile y APIs públicas

Las cookies son un mecanismo del **navegador**. Una app móvil nativa o un cliente API (curl, otro servicio) no tiene la maquinaria de cookies integrada de forma natural. Se puede hacer, pero es incómodo.

#### 6. Fijación de sesión

El atacante consigue que la víctima use un ID de sesión conocido por él. **Defensa:** regenerar el ID al hacer login (`req.session.regenerate()`).

#### 7. Expiración: idle vs absolute

Necesitas dos timeouts:
- **Idle timeout**: la sesión muere si pasan N minutos sin actividad.
- **Absolute timeout**: muere a las N horas de creada, hagas lo que hagas.

Sin idle, una sesión olvidada en un PC público vive para siempre. Sin absolute, un atacante con la cookie la mantiene viva indefinidamente.

#### 8. Limpieza del store

Sin TTL nativo (Redis lo tiene, una tabla SQL no), las sesiones expiradas no se borran solas y el store crece indefinidamente.

### Resumen del modelo clásico

✅ **Ventajas**
- Revocación inmediata (basta borrar del store).
- Logout global trivial (borras todas las sesiones del usuario).
- Trazabilidad completa (cada uso pasa por el servidor).
- Cookie en navegador es muy segura por defecto si configuras las flags.
- Identificador pequeño en cada request.

❌ **Inconvenientes**
- Cada request consulta el store → coste de I/O.
- Necesita store compartido para escalar horizontalmente.
- Vulnerable a CSRF si no configuras `SameSite`.
- Incómodo en mobile, APIs públicas y multi-dominio.
- Acoplamiento fuerte entre servicios y store de sesión.

> Aquí surge la pregunta: **¿se puede hacer autenticación sin que el servidor tenga que recordar nada?** Esa pregunta es la que da origen a JWT.

---

## 3. JWT: la respuesta stateless

### Qué es un JWT

Un **JWT** (JSON Web Token, RFC 7519) es un estándar para transmitir información entre dos partes de forma **firmada** y **verificable**. Permite sesiones *stateless*: el servidor no guarda nada, le basta con verificar la firma del token que el cliente envía.

### Estructura: tres partes separadas por puntos

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjE3MzAwMDB9.abc123firma
   ───── header ─────  ────────── payload ──────────  ─── signature ───
```

1. **Header** — qué algoritmo se usa para firmar (`HS256`, `RS256`, etc.)
2. **Payload** — los *claims* (datos), ej. id de usuario y expiración
3. **Signature** — firma criptográfica del header + payload con una clave secreta

Las dos primeras partes son **Base64URL**, no encriptadas. Cualquiera puede decodificarlas. La firma es lo que garantiza que no han sido modificadas.

> **Punto clave:** un JWT firmado **no es secreto, es verificable**. No metas contraseñas ni datos sensibles en el payload.

### Claims típicos

Claims estándar (RFC):

- `sub` — *subject*, normalmente el id del usuario
- `iss` — *issuer*, quién emitió el token
- `aud` — *audience*, para quién es
- `exp` — *expiration*, timestamp de caducidad
- `iat` — *issued at*, cuándo se emitió
- `nbf` — *not before*
- `jti` — id único del token (útil para revocación)

Y puedes añadir los tuyos. En un proyecto multi-tenant, `tenant_id` y `sub_tenant_id` viajarían como claims, así cada petición sabe a qué inquilino pertenece sin consultar la base de datos.

### Cómo se usa en una API

```
1. POST /login con usuario + contraseña
2. El servidor valida y devuelve un JWT firmado
3. El cliente lo guarda y lo envía en cada petición:
       Authorization: Bearer eyJhbGciOi...
4. El servidor verifica la firma y la expiración, y extrae los claims
   — sin tocar ninguna base de datos.
```

### Cómo JWT resuelve los problemas de las sesiones clásicas

| Problema en sesiones clásicas | Cómo lo resuelve JWT |
|---|---|
| Cada request consulta el store | El servidor solo verifica la firma — no toca DB |
| Necesita store compartido para escalar | Cualquier servidor con la clave pública puede validar |
| CSRF (cookies enviadas automáticamente) | El token va en `Authorization`, el navegador no lo manda solo |
| Incómodo en mobile / APIs | Trivial: solo es un header HTTP |
| Cross-domain complicado | El header viaja a cualquier dominio sin reglas raras |

### Algoritmos de firma

- **HS256** (HMAC + clave compartida): simple, ambas partes conocen la misma clave.
- **RS256 / ES256** (clave pública/privada): el emisor firma con la privada, cualquiera verifica con la pública. Mejor para sistemas distribuidos.

### Seguridad esencial con JWT

- **El payload es público.** Solo guarda lo no sensible.
- **Siempre valida la firma y la expiración** en el servidor.
- **Cuidado con `alg: none`** — un atacante puede mandar un token sin firma. Rechaza algoritmos no esperados.
- **Algorithm confusion**: si esperas RS256 y aceptas HS256, un atacante puede usar tu clave pública como clave HMAC. Fija el algoritmo explícitamente al verificar.
- **Dónde guardarlo**: `localStorage` es vulnerable a XSS; cookies `httpOnly` + `Secure` + `SameSite` son más seguras pero requieren protección CSRF.

---

## 4. El problema de los JWT y el refresh token

JWT resuelve la escalabilidad y el cross-domain, pero introduce **un problema serio**: si el token es robado, ¿cómo lo invalidas? La firma sigue siendo válida hasta `exp`.

### El dilema sin refresh token

Imagina que solo tienes un JWT (que llamamos *access token*). Tienes que elegir su duración:

**Opción A: token largo (ej. 7 días).**
- ✅ Cómodo: el usuario no tiene que reloguearse.
- ❌ Si lo roban, el atacante tiene 7 días dentro.
- ❌ **No puedes revocarlo** sin romper la naturaleza stateless.
- ❌ Para revocar, tendrías que consultar una blacklist en cada petición → pierdes la ventaja stateless de JWT.

**Opción B: token corto (ej. 15 min).**
- ✅ Si lo roban, daño limitado.
- ❌ El usuario tiene que hacer login cada 15 minutos. Inviable.

Cualquiera de las dos es mala. **El refresh token rompe el dilema.**

### La idea del refresh token

> Separar **lo que viaja mucho** (en cada petición a la API) de **lo que vive mucho** (la sesión persistente).

Se usan **dos tokens** con perfiles muy distintos:

| | Access token | Refresh token |
|---|---|---|
| Vida útil | Corta (15–60 min) | Larga (días o semanas) |
| Para qué sirve | Autenticar peticiones a la API | Obtener un nuevo access token |
| Dónde se envía | En cada request (`Authorization: Bearer`) | Solo al endpoint `/refresh` |
| Dónde se guarda | Memoria o cookie httpOnly | Cookie httpOnly + Secure |
| Estado en servidor | Stateless (solo firma) | Suele guardarse en DB/Redis para poder revocarlo |

El access caduca pronto (limita el daño si lo roban). El refresh permite renovarlo sin pedir credenciales otra vez.

---

## 5. Flujo de expiración del access token

### Flujo completo paso a paso

```
┌──────────┐                                      ┌──────────┐
│ Cliente  │                                      │ Servidor │
└────┬─────┘                                      └────┬─────┘
     │                                                 │
     │  1. POST /login (usuario + contraseña)          │
     ├────────────────────────────────────────────────►│
     │                                                 │
     │  2. { accessToken (15min), refreshToken (7d) }  │
     │◄────────────────────────────────────────────────┤
     │                                                 │
     │  3. GET /api/datos                              │
     │     Authorization: Bearer <accessToken>         │
     ├────────────────────────────────────────────────►│
     │                                                 │
     │  4. 200 OK { data }                             │
     │◄────────────────────────────────────────────────┤
     │                                                 │
     │            ... pasan 20 minutos ...             │
     │                                                 │
     │  5. GET /api/datos                              │
     │     Authorization: Bearer <accessToken>         │
     ├────────────────────────────────────────────────►│
     │                                                 │
     │  6. 401 Unauthorized                            │
     │     { error: "token_expired" }                  │
     │◄────────────────────────────────────────────────┤
     │                                                 │
     │  7. POST /auth/refresh                          │
     │     Cookie: refreshToken=...                    │
     ├────────────────────────────────────────────────►│
     │                                                 │
     │  8. { accessToken nuevo, refreshToken nuevo }   │
     │◄────────────────────────────────────────────────┤
     │                                                 │
     │  9. Reintenta GET /api/datos con el nuevo token │
     ├────────────────────────────────────────────────►│
     │                                                 │
     │ 10. 200 OK { data }                             │
     │◄────────────────────────────────────────────────┤
```

### Qué hace el cliente cuando detecta un 401

Un **interceptor HTTP** (Axios, fetch wrapper):

1. Intercepta cualquier respuesta 401 con código `token_expired`.
2. Llama a `/auth/refresh` enviando el refresh token.
3. Si el refresh va bien, guarda el nuevo access token y **reintenta la petición original**.
4. Si el refresh también falla, redirige a login.

```js
// Pseudocódigo
api.onResponseError(async (error, originalRequest) => {
  if (error.status === 401 && !originalRequest._retried) {
    originalRequest._retried = true;
    try {
      const { accessToken } = await api.post('/auth/refresh');
      saveAccessToken(accessToken);
      originalRequest.headers.Authorization = `Bearer ${accessToken}`;
      return api.request(originalRequest); // reintenta
    } catch {
      redirectToLogin();
    }
  }
  throw error;
});
```

El usuario **no se entera** de que el token expiró.

### Qué hace el servidor en `/auth/refresh`

```
1. Lee el refresh token de la cookie httpOnly.
2. Verifica su firma y expiración.
3. Comprueba en la base de datos / Redis que NO está revocado.
4. (Recomendado) Marca el refresh actual como usado.
5. Emite un access token nuevo + un refresh token nuevo.
6. Devuelve el access en el body y el refresh en cookie httpOnly.
```

### Refresh token rotation

Cada vez que se usa un refresh token, **se invalida y se emite uno nuevo**. Esto sirve para detectar robos.

### Casos borde a manejar

**Race condition con peticiones paralelas.** Si 5 llamadas fallan a la vez con 401, no quieres disparar 5 refreshes. Una única promesa de refresh en curso a la que se suscriben todas:

```js
let refreshPromise = null;
function refresh() {
  if (!refreshPromise) {
    refreshPromise = api.post('/auth/refresh')
      .finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}
```

**Refresh token expirado.** Cliente borra todo, redirige a login.

**Logout.** No basta borrar tokens del cliente: hay que invalidar el refresh en el servidor.

**Clock skew.** Permite un `clockTolerance` de unos segundos al verificar.

---

## 6. ¿Y si roban ambos tokens?

Respuesta corta incómoda: **si el atacante tiene ambos tokens, está dentro como tú**. No hay magia criptográfica que lo impida.

Lo importante es entender el **alcance del daño, cómo se detecta, y cómo se mitiga**.

### Escenario 1: solo roban el access token

El menos grave.
- El atacante hace peticiones autenticadas hasta que expire (15–60 min).
- No puede renovarlo (no tiene refresh).
- Al expirar, queda fuera automáticamente.

**Daño máximo:** vida restante del access token. Por eso se usan `exp` cortos.

### Escenario 2: roban el refresh token

Aquí la cosa se pone seria. **Sin protecciones**, el atacante mantiene la sesión viva indefinidamente.

Aquí entra **refresh token rotation con detección de reuso**:

```
Cada refresh token solo se puede usar UNA VEZ.
Al usarlo, se emite uno nuevo y el viejo queda marcado como "consumido".
Si alguien intenta usar un refresh consumido → ALERTA → invalidar toda la familia.
```

#### Cómo se detecta el robo

```
Estado inicial: víctima y atacante tienen el mismo refresh token RT1.

Caso A — el atacante refresca primero:
  Atacante: POST /refresh con RT1  →  recibe RT2 (nuevo)
  Servidor: marca RT1 como usado.

  Víctima (más tarde): POST /refresh con RT1
  Servidor: "RT1 ya fue usado pero la familia sigue activa → ROBO"
  → invalida RT1, RT2 y toda la cadena
  → fuerza re-login

Caso B — la víctima refresca primero:
  Víctima: POST /refresh con RT1  →  recibe RT2
  Atacante (después): POST /refresh con RT1
  Servidor: detecta lo mismo → invalida la familia.
```

> **Lo clave:** *uno de los dos* va a usar el token "viejo" tarde o temprano. Cuando lo haga, se detecta el robo con certeza, aunque no se sepa quién es el ladrón.

#### Qué hace el servidor al detectar reuso

1. **Invalida toda la familia** de refresh tokens descendientes.
2. **Cierra todas las sesiones activas** del usuario.
3. **Notifica al usuario** ("detectamos actividad sospechosa").
4. **Loguea el evento** para auditoría.
5. (Opcional) **Bloquea temporalmente** la cuenta o exige 2FA.

### Escenario 3: roban ambos

El peor caso. Pero **incluso aquí**, la rotación con detección de reuso sigue funcionando: la próxima vez que la víctima intente refrescar con su token viejo → se detecta el robo y se invalida todo. Solo si la víctima nunca vuelve a usar la app, el atacante pasa desapercibido.

### Defensas en profundidad

- **Vincular el token al contexto** (device fingerprinting, DPoP / token binding).
- **Detección de anomalías** (geolocalización imposible, login desde país inusual).
- **Limitar el alcance** (scopes mínimos, audience específico, step-up auth).
- **Almacenamiento seguro** (httpOnly + Secure + SameSite, HTTPS obligatorio).
- **Capacidad de revocar** (lista de `jti` revocados en Redis, endpoint `/sessions`).

> **La idea clave:** ningún sistema impide que un token robado funcione mientras es válido. La seguridad real está en *minimizar la ventana* (tokens cortos), *detectar el uso anómalo* (rotación + reuso) y *limitar el daño* (scopes, step-up auth).

---

## 7. ¿Cuál es entonces el sentido del refresh token?

Si ambos tokens pueden robarse, ¿qué aporta tener dos?

### El malentendido

Mucha gente cree que el refresh token es "más seguro" que el access. **No lo es** — criptográficamente son lo mismo.

El refresh existe para crear una **asimetría** entre dos cosas:

- Lo que viaja **mucho** (en cada petición a la API) → debe ser **fácil de invalidar**
- Lo que viaja **poco** (solo al renovar) → puede vivir **mucho tiempo**

### Qué te da el refresh token (de verdad)

#### 1. Tokens de acceso cortos sin sacrificar UX

El access vive 15 minutos: si lo roban, el daño es de 15 minutos. La sesión sigue siendo larga gracias al refresh.

> Reduce la ventana de exposición del token que **más se expone**. El access viaja en cada petición — cuanto más viaja, más probable es que se filtre.

#### 2. Capacidad de revocar sin romper "stateless"

Las APIs validan el access sin tocar la DB: solo firma + `exp`. Eso es lo que hace JWT escalable. Pero el access **no se puede revocar**.

¿Cómo lo invalidas? **Indirectamente, vía el refresh.**

```
Usuario hace logout / cambia contraseña / detectas robo
         │
         ▼
  Invalidas el refresh token en la DB
         │
         ▼
  El access actual sigue funcionando ≤ 15 min
         │
         ▼
  Cuando intenta refrescar → bloqueado → fuera para siempre
```

> El refresh es tu **palanca de revocación**. Como solo se usa al renovar, consultar la DB ahí no afecta al rendimiento de la API. Las peticiones normales siguen siendo stateless.

#### 3. Detección de robos vía rotación

**Imposible con un solo token.** Si solo tienes access, dos personas usándolo en paralelo es indistinguible de la víctima usándolo en móvil y portátil. La rotación necesita un token usado **infrecuentemente y de forma controlada** — ese es el refresh.

#### 4. Asimetría de almacenamiento y exposición

| | Access token | Refresh token |
|---|---|---|
| Dónde vive | Memoria o cookie | Cookie `httpOnly` + `Secure` + `SameSite=Strict` |
| Quién lo lee | JS del cliente | **Nadie** — el JS ni siquiera puede verlo |
| Vulnerable a XSS | Sí (si está accesible al JS) | No (httpOnly lo bloquea) |
| Endpoints donde viaja | Todos los de la API | Solo `/auth/refresh` |
| Dominios donde viaja | Posiblemente varios | Uno (el del auth) |

El refresh vive en un **bunker** que el JavaScript no puede ni leer. Robarlo requiere o un XSS muy específico, o acceso físico, o MITM con HTTPS roto.

El access **tiene que** estar accesible al JS porque hay que ponerlo en cabeceras. Es inevitablemente más expuesto, pero vive 15 minutos.

### Una analogía que ayuda

Piensa en una caja fuerte de hotel:

- La **llave de la habitación** (access) la llevas todo el día encima. Se cae fácil del bolsillo. Pero solo abre tu habitación y solo durante tu estancia.
- El **pasaporte** (refresh) está en la caja fuerte. Solo lo sacas cuando lo necesitas. Es más valioso, pero está mucho mejor guardado.

Tener "una llave que vale para todo" sería peor: o la llevas siempre encima (insegura) o nunca la sacas (inútil).

### La respuesta directa

El refresh token no es irrobable. Es **mucho más difícil de robar** que el access (httpOnly, un solo endpoint), y **además** te permite tres cosas que con un único token no podrías:

1. Tener access tokens cortos sin obligar al usuario a reloguearse.
2. Mantener la API stateless conservando capacidad de revocar.
3. Detectar robos mediante rotación con detección de reuso.

> **No es seguridad absoluta, es elevar el coste del ataque y minimizar el daño cuando ocurre** — que es lo que es toda la seguridad real.

---

## 8. Comparación final y cuándo elegir cada modelo

### Tabla comparativa

| Aspecto | Sesión clásica | JWT solo | JWT + Refresh |
|---|---|---|---|
| Estado en servidor | Sí (cada request) | No | Solo en refresh |
| Revocación inmediata | Trivial | Imposible sin blacklist | Vía refresh, fácil |
| Escalabilidad | Necesita store compartido | Natural | Natural |
| CSRF | Vulnerable (mitigable con `SameSite`) | No aplica | No aplica para access |
| XSS | Mitigable (HttpOnly) | Más expuesto | Mixto (refresh seguro, access expuesto) |
| Tamaño en cada request | Pequeño | Grande | Grande (solo access) |
| Mobile / APIs | Incómodo | Trivial | Trivial |
| Cross-domain | Complicado | Simple | Simple |
| Logout global | Trivial | Requiere blacklist | Vía refresh, fácil |
| Detección de robos | Difícil | Imposible | **Posible** (rotación) |
| Complejidad de implementación | Baja | Media | Alta |

### Cuándo elegir cada uno

**Sesión clásica** si:
- Es una webapp tradicional, mismo dominio, navegador.
- No necesitas escalabilidad extrema.
- Quieres lo más simple y seguro por defecto.
- El equipo no tiene experiencia con tokens y revocación.

**JWT solo** (sin refresh) si:
- API completamente stateless donde la revocación no es crítica.
- Tokens de muy corta vida en flujos transaccionales (ej. confirmación por email).
- Servicio a servicio, no usuarios humanos.

**JWT + Refresh con rotación** si:
- API consumida por mobile / SPA / múltiples clientes.
- Microservicios distribuidos.
- Multi-tenant con dominios custom.
- Necesitas balance entre stateless y poder revocar.

### La idea final

> Cada modelo resuelve los problemas del anterior, pero introduce los suyos propios.
>
> - **Sesión clásica** delega complejidad al servidor (lo recuerda todo).
> - **JWT** delega complejidad al cliente y al diseño (autocontenido pero difícil de revocar).
> - **JWT + Refresh** combina lo mejor de ambos a costa de implementar rotación, detección de reuso y manejo de dos tokens.
>
> Mucho del entusiasmo histórico por JWT venía de "es stateless y escala". Hoy sabemos que la mayoría de apps **no necesitan ese nivel de escalabilidad** y que mantener una sesión en Redis es trivial. **JWT no es automáticamente la opción correcta** — es una herramienta con un perfil de trade-offs distinto. Elige según el problema, no según la moda.

---

*Documento generado a partir de una sesión de aprendizaje progresivo sobre autenticación web.*
