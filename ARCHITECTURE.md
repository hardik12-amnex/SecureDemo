# SecureApp — System Architecture Diagram

> **Version:** 1.0.0 | **Spring Boot:** 4.0.3 | **Java:** 21 | **Date:** March 12, 2026

---

## 1. High-Level System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                       │
│                                                                                 │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │                   Angular Frontend (localhost:4200)                      │   │
│   │                                                                          │   │
│   │   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐    │   │
│   │   │  WebCrypto API   │   │  DPoP Service    │   │  HTTP Interceptor│    │   │
│   │   │  ──────────────  │   │  ──────────────  │   │  ──────────────  │    │   │
│   │   │ • Generate ECDSA │──▶│ • Build proof JWT│──▶│ • Attach DPoP   │    │   │
│   │   │   P-256 keypair  │   │ • Sign with      │   │   header        │    │   │
│   │   │ • Store private  │   │   private key    │   │ • Attach session│    │   │
│   │   │   key in memory  │   │ • Fresh jti/iat  │   │   cookie        │    │   │
│   │   └──────────────────┘   └──────────────────┘   └────────┬───────┘    │   │
│   │                                                           │            │   │
│   └───────────────────────────────────────────────────────────┼────────────┘   │
│                                                               │                 │
└───────────────────────────────────────────────────────────────┼─────────────────┘
                                                                │
                      HTTPS (Port 8080)                         │
                      Cookie: JSESSIONID=xxx                    │
                      Header: DPoP: <signed-jwt>                │
                                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SERVER LAYER (Spring Boot 4.0.3)                        │
│                          Context Path: /api                                     │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    SECURITY FILTER CHAIN                                │   │
│   │                    (See Section 2 for details)                          │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│   ┌─────────────────────────────────────▼───────────────────────────────────┐   │
│   │                    MVC INTERCEPTOR CHAIN                                │   │
│   │                    AuthorizationInterceptor                             │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│   ┌─────────────────────────────────────▼───────────────────────────────────┐   │
│   │                    CONTROLLER LAYER                                     │   │
│   │    AuthController          DashboardController                          │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│   ┌─────────────────────────────────────▼───────────────────────────────────┐   │
│   │                    SERVICE LAYER                                        │   │
│   │    AuthService         DPoPSessionBindingService                        │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
│   ┌─────────────────────────────────────▼───────────────────────────────────┐   │
│   │                    REPOSITORY / DATA LAYER                              │   │
│   │    UserRepository          RoleRepository                               │   │
│   └─────────────────────────────────────┬───────────────────────────────────┘   │
│                                         │                                       │
└─────────────────────────────────────────┼───────────────────────────────────────┘
                                          │
                                          │  JDBC
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          DATA LAYER (PostgreSQL :5432)                           │
│                          Database: secureapp_db                                 │
│                                                                                 │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│   │    users      │  │    roles     │  │  user_roles   │  │ SPRING_SESSION   │   │
│   │  ──────────── │  │  ────────── │  │  ──────────── │  │ ──────────────── │   │
│   │ id           │  │ id           │  │ user_id  (FK) │  │ PRIMARY_ID       │   │
│   │ username     │  │ name         │  │ role_id  (FK) │  │ SESSION_ID       │   │
│   │ email        │  │ description  │  └──────────────┘  │ EXPIRY_TIME      │   │
│   │ password     │  │ created_at   │                     │ PRINCIPAL_NAME   │   │
│   │  (BCrypt-12) │  │ updated_at   │                     └────────┬─────────┘   │
│   │ first_name   │  └──────────────┘                              │             │
│   │ last_name    │                                     ┌──────────▼─────────┐   │
│   │ enabled      │                                     │ SPRING_SESSION_    │   │
│   │ created_at   │                                     │    ATTRIBUTES      │   │
│   │ last_login   │                                     │ ──────────────────│   │
│   └──────────────┘                                     │ SESSION_PRIMARY_ID│   │
│                                                        │ ATTRIBUTE_NAME    │   │
│                                                        │ ATTRIBUTE_BYTES   │   │
│                                                        │  (DPoP keys,     │   │
│                                                        │   user attrs)    │   │
│                                                        └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Filter Chain — Detailed Request Pipeline

```
                            ┌──────────────────┐
                            │  INCOMING REQUEST │
                            │  GET /api/dashboard│
                            │  Cookie: JSESSIONID│
                            │  DPoP: <jwt>       │
                            └────────┬───────────┘
                                     │
              ┌──────────────────────▼──────────────────────┐
              │          ① CORS Filter (Spring)             │
              │  ──────────────────────────────────────────  │
              │  • Validates Origin: http://localhost:4200   │
              │  • Handles preflight OPTIONS requests        │
              │  • Exposes DPoP header to client             │
              │  ✗ Origin not allowed → 403 Forbidden        │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ CORS OK
              ┌──────────────────────▼──────────────────────┐
              │          ② CSRF Filter (Spring)             │
              │  ──────────────────────────────────────────  │
              │  • CookieCsrfTokenRepository (HttpOnly=off) │
              │  • Validates X-XSRF-TOKEN on POST/PUT/DELETE │
              │  • GET requests skip CSRF check              │
              │  ✗ Missing/invalid CSRF → 403 Forbidden      │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ CSRF OK
              ┌──────────────────────▼──────────────────────┐
              │     ③ DPoPAuthenticationFilter [CUSTOM]     │
              │  ──────────────────────────────────────────  │
              │  Excluded: /auth/login, /auth/register,     │
              │            /auth/logout, /health             │
              │                                              │
              │  Step 1: Extract DPoP header                 │
              │  Step 2: Parse & verify JWT signature (ES256)│
              │  Step 3: Validate typ=dpop+jwt               │
              │  Step 4: Validate htm (HTTP method)          │
              │  Step 5: Validate htu (request URI)          │
              │  Step 6: Validate iat (within ±300s)         │
              │  Step 7: Check jti uniqueness (Caffeine)     │
              │  Step 8: Compare JWK thumbprint vs session   │
              │  ✗ Any failure → 401 JSON response           │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ DPoP Valid
              ┌──────────────────────▼──────────────────────┐
              │     ④ SessionValidationFilter [CUSTOM]      │
              │  ──────────────────────────────────────────  │
              │  Excluded: /auth/login, /auth/register,     │
              │            /auth/logout, /health             │
              │                                              │
              │  Step 1: Session exists? (getSession(false)) │
              │  Step 2: Session expired? (time-based check) │
              │  Step 3: SecurityContext has auth user?       │
              │  Step 4: Session has "username" attribute?    │
              │  ✗ Any failure → 401 JSON response           │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Session Valid
              ┌──────────────────────▼──────────────────────┐
              │     ⑤ SecurityHeadersFilter [CUSTOM]        │
              │  ──────────────────────────────────────────  │
              │  Adds to EVERY response:                     │
              │  • Content-Security-Policy                   │
              │  • X-Frame-Options: DENY                     │
              │  • X-Content-Type-Options: nosniff           │
              │  • Strict-Transport-Security (HSTS)          │
              │  • X-XSS-Protection: 1; mode=block           │
              │  • Referrer-Policy: strict-origin-...        │
              │  • Permissions-Policy: camera=(), ...        │
              │  • Cache-Control: no-store                   │
              └──────────────────────┬──────────────────────┘
                                     │
              ┌──────────────────────▼──────────────────────┐
              │     ⑥ Spring Security Authorization         │
              │  ──────────────────────────────────────────  │
              │  .authorizeHttpRequests:                      │
              │    /auth/login, /auth/register → permitAll() │
              │    /auth/logout, /health      → permitAll() │
              │    /** (everything else)       → authenticated│
              │  ✗ Not authenticated → 401 / redirect        │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Authenticated
        ═════════════════════════════╪═══════════════════════════
                  FILTER CHAIN END │  MVC INTERCEPTOR CHAIN START
        ═════════════════════════════╪═══════════════════════════
              ┌──────────────────────▼──────────────────────┐
              │     ⑦ AuthorizationInterceptor [CUSTOM]     │
              │  ──────────────────────────────────────────  │
              │  Excluded: /auth/*, /health, /error          │
              │                                              │
              │  Step 1: Get path from request               │
              │  Step 2: Get user + roles from SecurityContext│
              │  Step 3: Lookup allowed roles in             │
              │          RolePermissionMapping                │
              │  Step 4: Check user roles vs allowed roles   │
              │                                              │
              │  Permission Map:                             │
              │    /admin/**           → [ROLE_ADMIN]        │
              │    /activity/admin/**  → [ROLE_ADMIN]        │
              │    /activity/profile/**→ [ROLE_USER, ADMIN]  │
              │    /activity/action/** → [ROLE_USER, ADMIN]  │
              │    /dashboard/**       → [ROLE_USER, ADMIN]  │
              │    (no mapping)        → allow (Spring rules)│
              │                                              │
              │  ✗ Role not allowed → 403 JSON response      │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Authorized
              ┌──────────────────────▼──────────────────────┐
              │     ⑧ @PreAuthorize (Method Security)       │
              │  ──────────────────────────────────────────  │
              │  • @PreAuthorize("isAuthenticated()")        │
              │  • @PreAuthorize("hasRole('ADMIN')")         │
              │  ✗ Access denied → 403                       │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Authorized
              ┌──────────────────────▼──────────────────────┐
              │          ⑨ CONTROLLER METHOD                │
              │  ──────────────────────────────────────────  │
              │  • Process business logic                    │
              │  • Return ApiResponse<T> JSON                │
              └──────────────────────┬──────────────────────┘
                                     │
                            ┌────────▼───────────┐
                            │  HTTP RESPONSE      │
                            │  200 OK / JSON body  │
                            │  + Security headers  │
                            │  + Set-Cookie (if    │
                            │    session created)  │
                            └──────────────────────┘
```

---

## 3. Login Flow — DPoP Key Binding & Session Creation

```
   CLIENT                                              SERVER
     │                                                    │
     │  ┌─────────────────────────────────────────────┐   │
     │  │ 1. Generate ECDSA P-256 Keypair             │   │
     │  │    crypto.subtle.generateKey('ECDSA', P-256) │   │
     │  │    → privateKey (kept in memory)             │   │
     │  │    → publicKey  (embedded in DPoP JWT)       │   │
     │  └─────────────────────────────────────────────┘   │
     │                                                    │
     │  ┌─────────────────────────────────────────────┐   │
     │  │ 2. Build DPoP Proof JWT                     │   │
     │  │    Header: {                                 │   │
     │  │      "typ": "dpop+jwt",                     │   │
     │  │      "alg": "ES256",                        │   │
     │  │      "jwk": { kty, crv, x, y }              │   │
     │  │    }                                         │   │
     │  │    Payload: {                                │   │
     │  │      "htm": "POST",                         │   │
     │  │      "htu": "http://…/api/auth/login",      │   │
     │  │      "iat": <unix-timestamp>,                │   │
     │  │      "jti": "<random-uuid>"                  │   │
     │  │    }                                         │   │
     │  │    Sign with privateKey → compactJWT         │   │
     │  └─────────────────────────────────────────────┘   │
     │                                                    │
     │  POST /api/auth/login                              │
     │  Content-Type: application/json                    │
     │  DPoP: eyJhbGciOi....<signed-jwt>                  │
     │  Body: { "username": "testuser",                   │
     │          "password": "UserPass123!" }               │
     │ ──────────────────────────────────────────────────▶ │
     │                                                    │
     │                    ┌───────────────────────────────────────────────────┐
     │                    │ 3. AuthController.login()                         │
     │                    │                                                   │
     │                    │  a. Extract DPoP header                           │
     │                    │     → Missing? Return 400                         │
     │                    │                                                   │
     │                    │  b. AuthService.login(username, password)         │
     │                    │     → Load user from DB                           │
     │                    │     → BCrypt.matches(password, hash)              │
     │                    │     → Check enabled, accountNonLocked             │
     │                    │     → Update lastLogin timestamp                  │
     │                    │     → Return UserResponse                         │
     │                    │                                                   │
     │                    │  c. SESSION ROTATION                              │
     │                    │     → oldSession.invalidate()                     │
     │                    │     → newSession = request.getSession(true)       │
     │                    │     → Store userId, username, roles               │
     │                    │                                                   │
     │                    │  d. DPoPSessionBindingService                     │
     │                    │     .validateAndBindKey(proof, method, uri, sess) │
     │                    │     → DPoPProofValidator.validate(proof)          │
     │                    │       → Parse JWT                                │
     │                    │       → Verify typ = dpop+jwt                    │
     │                    │       → Verify alg = ES256                       │
     │                    │       → Extract JWK public key                   │
     │                    │       → Verify signature with public key         │
     │                    │       → Validate htm, htu, iat, jti              │
     │                    │       → Compute JWK Thumbprint                   │
     │                    │     → Store in session:                           │
     │                    │       DPOP_PUBLIC_KEY = jwk.toJSON()             │
     │                    │       DPOP_JWK_THUMBPRINT = thumbprint           │
     │                    │     → Session persisted to PostgreSQL via JDBC    │
     │                    └───────────────────────────────────────────────────┘
     │                                                    │
     │ ◀────────────────────────────────────────────────── │
     │  200 OK                                            │
     │  Set-Cookie: JSESSIONID=<new-id>;                  │
     │              Path=/; HttpOnly; Secure;              │
     │              SameSite=Strict; Max-Age=900           │
     │  Body: {                                           │
     │    "success": true,                                │
     │    "message": "Login successful",                  │
     │    "data": { id, username, email, roles, ... }     │
     │  }                                                 │
     │                                                    │
     │  ┌─────────────────────────────────────────────┐   │
     │  │ 4. Client stores:                           │   │
     │  │    • JSESSIONID cookie (automatic)           │   │
     │  │    • privateKey in memory (for future proofs)│   │
     │  └─────────────────────────────────────────────┘   │
     │                                                    │
```

---

## 4. Authenticated Request Flow — DPoP + Session Verification

```
   CLIENT                                              SERVER
     │                                                    │
     │  ┌─────────────────────────────────────────────┐   │
     │  │ Build FRESH DPoP proof for this request     │   │
     │  │  htm: "GET"                                  │   │
     │  │  htu: "http://…/api/dashboard"               │   │
     │  │  iat: <current-timestamp>                    │   │
     │  │  jti: "<new-random-uuid>"                    │   │
     │  │  Sign with SAME privateKey from login        │   │
     │  └─────────────────────────────────────────────┘   │
     │                                                    │
     │  GET /api/dashboard                                │
     │  Cookie: JSESSIONID=abc123                         │
     │  DPoP: eyJhbGciOi....<new-signed-jwt>              │
     │ ──────────────────────────────────────────────────▶ │
     │                                                    │
     │                    ┌───────────────────────────────────────────────────┐
     │                    │                                                   │
     │                    │  ③ DPoPAuthenticationFilter                       │
     │                    │  ├── Extract DPoP header                          │
     │                    │  ├── Parse JWT, verify ES256 signature            │
     │                    │  ├── Validate htm="GET", htu matches URL          │
     │                    │  ├── Validate iat within ±300s                    │
     │                    │  ├── Check jti not in Caffeine cache (replay)     │
     │                    │  ├── Load session → get stored JWK thumbprint     │
     │                    │  └── Compare proof thumbprint == stored thumbprint│
     │                    │      ✓ Match → continue chain                     │
     │                    │      ✗ Mismatch → 401 "key does not match"        │
     │                    │                                                   │
     │                    │  ④ SessionValidationFilter                        │
     │                    │  ├── Session exists?                              │
     │                    │  ├── Session not expired?                         │
     │                    │  ├── SecurityContext has authenticated user?      │
     │                    │  └── Session has "username" attribute?            │
     │                    │      ✓ Valid → continue chain                     │
     │                    │                                                   │
     │                    │  ⑦ AuthorizationInterceptor                      │
     │                    │  ├── Path: /dashboard                             │
     │                    │  ├── Allowed: [ROLE_USER, ROLE_ADMIN]             │
     │                    │  ├── User roles: [ROLE_USER]                      │
     │                    │  └── ROLE_USER ∈ allowed? YES                     │
     │                    │      ✓ Authorized → continue                      │
     │                    │                                                   │
     │                    │  ⑨ DashboardController.dashboard()                │
     │                    │  └── Return dashboard data                        │
     │                    └───────────────────────────────────────────────────┘
     │                                                    │
     │ ◀────────────────────────────────────────────────── │
     │  200 OK                                            │
     │  X-Frame-Options: DENY                             │
     │  X-Content-Type-Options: nosniff                   │
     │  Strict-Transport-Security: max-age=31536000...    │
     │  Content-Security-Policy: default-src 'self'...    │
     │  Cache-Control: no-store, no-cache...              │
     │  Body: {                                           │
     │    "success": true,                                │
     │    "data": {                                       │
     │      "message": "Welcome to dashboard, testuser",  │
     │      "timestamp": 1741785600000                    │
     │    }                                               │
     │  }                                                 │
     │                                                    │
```

---

## 5. Component Dependency Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CONFIG LAYER                                   │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  SecurityConfig   │  │  SessionConfig   │  │     WebMvcConfig         │  │
│  │  ────────────────│  │  ──────────────  │  │  ────────────────────── │  │
│  │ • Filter chain   │  │ • @EnableJdbc-   │  │ • Registers             │  │
│  │ • CORS config    │  │   HttpSession    │  │   AuthorizationInter-   │  │
│  │ • CSRF config    │  │ • 15-min timeout │  │   ceptor                │  │
│  │ • Session mgmt   │  └──────────────────┘  │ • Exclude paths:        │  │
│  │ • Auth rules     │                        │   /auth/*, /health      │  │
│  │ • Header config  │                        └──────────┬───────────────┘  │
│  └────────┬─────────┘                                   │                  │
│           │ registers                                   │ registers        │
│           ▼                                             ▼                  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         FILTER / INTERCEPTOR LAYER                   │  │
│  │                                                                      │  │
│  │  ┌──────────────────────┐  ┌─────────────────────┐                  │  │
│  │  │DPoPAuthentication-   │  │SessionValidation-   │                  │  │
│  │  │    Filter             │  │    Filter            │                  │  │
│  │  │ ──────────────────── │  │ ───────────────────  │                  │  │
│  │  │ • OncePerRequest     │  │ • OncePerRequest    │                  │  │
│  │  │ • Before UsernameP.. │  │ • After DPoP filter │                  │  │
│  │  │ ─────────────────    │  │ ────────────────    │                  │  │
│  │  │ Uses:                │  │ Uses:               │                  │  │
│  │  │ • DPoPProofValidator │  │ • SecurityContext    │                  │  │
│  │  │ • DPoPReplayProtect..│  │ • HttpSession        │                  │  │
│  │  │ • HttpSession        │  └─────────────────────┘                  │  │
│  │  └──────────┬───────────┘                                            │  │
│  │             │                 ┌────────────────────────┐              │  │
│  │             │                 │SecurityHeadersFilter   │              │  │
│  │             │                 │ ──────────────────── │              │  │
│  │             │                 │ • Servlet Filter      │              │  │
│  │             │                 │ • CSP, HSTS, X-Frame  │              │  │
│  │             │                 │ • Cache-Control       │              │  │
│  │             │                 └────────────────────────┘              │  │
│  │             │                                                        │  │
│  │             │                 ┌────────────────────────┐              │  │
│  │             │                 │AuthorizationInterceptor│              │  │
│  │             │                 │ ──────────────────── │              │  │
│  │             │                 │ • HandlerInterceptor  │              │  │
│  │             │                 │ Uses:                 │              │  │
│  │             │                 │ • RolePermissionMapping│              │  │
│  │             │                 │ • SecurityUtils        │              │  │
│  │             │                 └───────────┬────────────┘              │  │
│  └─────────────┼─────────────────────────────┼──────────────────────────┘  │
└────────────────┼─────────────────────────────┼──────────────────────────────┘
                 │                             │
                 ▼                             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            DPoP LAYER                                        │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐  │
│  │  DPoPProofValidator    │  │  DPoPSessionBindingService                 │  │
│  │  ──────────────────── │  │  ──────────────────────────────────────── │  │
│  │  • Parse JWT           │  │  • Called at login                        │  │
│  │  • Verify typ, alg     │  │  • Validates proof via DPoPProofValidator │  │
│  │  • Verify ES256 sig    │  │  • Stores in session:                    │  │
│  │  • Validate htm, htu   │  │    - DPOP_PUBLIC_KEY (JWK JSON)          │  │
│  │  • Validate iat, jti   │  │    - DPOP_JWK_THUMBPRINT                 │  │
│  │  • Compute thumbprint  │  └────────────────────────────────────────────┘  │
│  └────────────────────────┘                                                  │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐  │
│  │DPoPReplayProtection-   │  │  DPoPConstants                            │  │
│  │    Service              │  │  ──────────────────────────────────────── │  │
│  │ ──────────────────── │  │  • DPOP_HEADER = "DPoP"                    │  │
│  │ • Caffeine cache      │  │  • DPOP_TOKEN_TYPE = "dpop+jwt"            │  │
│  │ • 100K entries max    │  │  • MAX_PROOF_AGE = 300s                    │  │
│  │ • 300s TTL per jti    │  │  • JTI_CACHE_MAX_SIZE = 100K              │  │
│  │ • isJtiUnique(jti)    │  │  • SESSION_ATTR_DPOP_JWK_THUMBPRINT       │  │
│  └────────────────────────┘  └────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────┐                                                  │
│  │DPoPValidationException │  Thrown on any validation failure → 401          │
│  └────────────────────────┘                                                  │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                          CONTROLLER LAYER                                    │
│                                                                              │
│  ┌──────────────────────────────┐  ┌──────────────────────────────────────┐  │
│  │  AuthController              │  │  DashboardController                 │  │
│  │  ────────────────────────── │  │  ──────────────────────────────────│  │
│  │  POST /auth/register         │  │  GET /health          [Public]       │  │
│  │  POST /auth/login            │  │  GET /dashboard        [USER+ADMIN]  │  │
│  │  POST /auth/logout           │  │  GET /admin/users      [ADMIN only]  │  │
│  │  GET  /auth/me               │  │                                      │  │
│  │  ──────────────────────────  │  │  Uses:                               │  │
│  │  Uses:                       │  │  • @PreAuthorize                     │  │
│  │  • AuthService               │  │  • HttpSession                       │  │
│  │  • DPoPSessionBindingService │  └──────────────────────────────────────┘  │
│  │  • HttpSession               │                                            │
│  └──────────────────────────────┘                                            │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                          SERVICE LAYER                                       │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  AuthService                                                           │  │
│  │  ──────────────────────────────────────────────────────────────────── │  │
│  │  • register(SignUpRequest) → validate, hash password, assign ROLE_USER │  │
│  │  • login(LoginRequest) → find user, verify BCrypt, check enabled      │  │
│  │  • getUserById(id) → fetch user, return UserResponse                  │  │
│  │  • getUserByUsername(username)                                          │  │
│  │  Uses: UserRepository, RoleRepository, PasswordEncoder (BCrypt-12)    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  CustomUserDetailsService (implements UserDetailsService)              │  │
│  │  ──────────────────────────────────────────────────────────────────── │  │
│  │  • loadUserByUsername() → returns Spring Security UserDetails          │  │
│  │  • Maps User entity + roles → GrantedAuthority objects                │  │
│  │  Uses: UserRepository                                                 │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                          REPOSITORY LAYER (Spring Data JPA)                  │
│                                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────────┐  │
│  │  UserRepository          │  │  RoleRepository                          │  │
│  │  ────────────────────── │  │  ──────────────────────────────────────│  │
│  │  • findByUsername()      │  │  • findByName()                          │  │
│  │  • findByEmail()         │  └──────────────────────────────────────────┘  │
│  │  • existsByUsername()    │                                                │  │
│  │  • existsByEmail()       │                                                │  │
│  └──────────────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Session Lifecycle & Storage

```
 ┌─────────────┐                     ┌──────────────────────────────────┐
 │  LOGIN       │                     │  PostgreSQL: SPRING_SESSION      │
 │  POST /auth/ │                     │  + SPRING_SESSION_ATTRIBUTES     │
 │  login       │                     └──────────┬───────────────────────┘
 └──────┬──────┘                                 │
        │                                        │
        ▼                                        │
 ┌──────────────────────────────┐                │
 │ 1. Invalidate old session    │   DELETE ──────┤
 │    oldSession.invalidate()   │                │
 └──────────────┬───────────────┘                │
                │                                │
                ▼                                │
 ┌──────────────────────────────┐                │
 │ 2. Create new session        │   INSERT ──────┤
 │    request.getSession(true)  │                │
 │    → New JSESSIONID generated│                │
 └──────────────┬───────────────┘                │
                │                                │
                ▼                                │
 ┌──────────────────────────────┐                │
 │ 3. Store user attributes     │   INSERT attrs─┤
 │    session.setAttribute:     │                │
 │    • "userId"    → Long      │                │
 │    • "username"  → String    │                │
 │    • "roles"     → Set<Str>  │                │
 └──────────────┬───────────────┘                │
                │                                │
                ▼                                │
 ┌──────────────────────────────┐                │
 │ 4. Bind DPoP public key      │   INSERT attrs─┤
 │    session.setAttribute:     │                │
 │    • "DPOP_PUBLIC_KEY"       │                │
 │      → JWK JSON string      │                │
 │    • "DPOP_JWK_THUMBPRINT"   │                │
 │      → Base64URL thumbprint  │                │
 └──────────────┬───────────────┘                │
                │                                │
                ▼                                │
 ┌──────────────────────────────┐                │
 │ 5. Set-Cookie sent to client │                │
 │    JSESSIONID=<new-id>       │                │
 │    Path=/; HttpOnly; Secure  │                │
 │    SameSite=Strict           │                │
 │    Max-Age=900 (15 min)      │                │
 └──────────────────────────────┘                │
                                                 │
 ┌──────────────┐                                │
 │  EACH REQUEST│                                │
 └──────┬───────┘                                │
        ▼                                        │
 ┌──────────────────────────────┐                │
 │ Server loads session from DB │   SELECT ──────┤
 │ by JSESSIONID cookie value   │                │
 │ → Validates DPoP thumbprint  │                │
 │ → Validates session attrs    │                │
 │ → Updates LAST_ACCESSED_TIME │   UPDATE ──────┤
 └──────────────────────────────┘                │
                                                 │
 ┌──────────────┐                                │
 │  LOGOUT       │                                │
 │  POST /auth/ │                                │
 │  logout       │                                │
 └──────┬───────┘                                │
        ▼                                        │
 ┌──────────────────────────────┐                │
 │ session.invalidate()         │   DELETE ──────┘
 │ → Removes from DB            │
 │ → JSESSIONID cookie cleared  │
 │ → DPoP binding destroyed     │
 └──────────────────────────────┘
```

---

## 7. DPoP Proof-of-Possession — Attack Prevention Model

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   ATTACK SCENARIOS & DPoP PROTECTION                     │
└──────────────────────────────────────────────────────────────────────────┘

  SCENARIO 1: Session Cookie Theft (XSS / Network Sniffing)
  ──────────────────────────────────────────────────────────
  
    Attacker steals: JSESSIONID=abc123
    Attacker sends:  GET /api/dashboard
                     Cookie: JSESSIONID=abc123
                     (no DPoP header)
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       "Missing DPoP proof header" → 401
    
    ┌─────────────────────────────────────────────┐
    │ Even with the cookie, the attacker cannot    │
    │ forge a DPoP proof because they don't have   │
    │ the client's ECDSA private key (which never  │
    │ leaves the browser's memory).                │
    └─────────────────────────────────────────────┘


  SCENARIO 2: DPoP Proof Replay Attack
  ────────────────────────────────────
  
    Attacker captures a valid DPoP proof from network traffic.
    Attacker replays the same proof on a different request.
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       Step 7: jti already in Caffeine cache
       "DPoP proof replay detected" → 401
    
    ┌─────────────────────────────────────────────┐
    │ Each DPoP proof has a unique jti (JWT ID).   │
    │ The server caches seen jtis for 300 seconds. │
    │ Reusing the same jti is immediately detected.│
    └─────────────────────────────────────────────┘


  SCENARIO 3: Stolen Key + Different Session
  ──────────────────────────────────────────
  
    Attacker has their OWN keypair and a stolen session cookie.
    Attacker generates a valid DPoP proof with THEIR key.
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       Step 8: JWK thumbprint mismatch
       Proof thumbprint ≠ Session-bound thumbprint
       "DPoP proof key does not match session-bound key" → 401
    
    ┌─────────────────────────────────────────────┐
    │ The public key is bound to the session at    │
    │ login time. A different key produces a        │
    │ different thumbprint → mismatch → rejected.  │
    └─────────────────────────────────────────────┘


  SCENARIO 4: Session Fixation
  ───────────────────────────
  
    Attacker plants a known session ID before the victim logs in.
    
    AuthController.login() → ✗ PREVENTED
       Step c: oldSession.invalidate()
               newSession = request.getSession(true)
       → Old session ID destroyed, new ID generated
       → Attacker's known session ID is useless
    
    ┌─────────────────────────────────────────────┐
    │ Session rotation at login ensures the old    │
    │ session ID (potentially planted by attacker) │
    │ is completely destroyed. The new session     │
    │ gets a cryptographically random ID.          │
    └─────────────────────────────────────────────┘


  SCENARIO 5: Expired/Stale DPoP Proof
  ────────────────────────────────────
  
    Client sends a DPoP proof created 10 minutes ago.
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       Step 6: |now - iat| > 300 seconds
       "proof expired or too far in the future" → 401
    
    ┌─────────────────────────────────────────────┐
    │ DPoP proofs are valid for ±5 minutes only.   │
    │ This limits the window for proof interception │
    │ and reuse.                                    │
    └─────────────────────────────────────────────┘
```

---

## 8. Entity-Relationship Diagram

```
┌────────────────────────────┐       ┌────────────────────┐
│          users              │       │       roles         │
│ ──────────────────────────│       │ ────────────────── │
│ PK  id          BIGSERIAL  │       │ PK  id    BIGSERIAL │
│     username    VARCHAR(100)│◄──┐   │     name  VARCHAR(50)│
│     email       VARCHAR(255)│   │   │     description     │
│     password    TEXT (BCrypt)│   │   │     created_at      │
│     first_name  VARCHAR(100)│   │   │     updated_at      │
│     last_name   VARCHAR(100)│   │   └─────────┬──────────┘
│     phone_number VARCHAR(20)│   │             │
│     address     TEXT        │   │             │
│     enabled     BOOLEAN     │   │             │
│     account_non_expired     │   │             │
│     account_non_locked      │   │    ┌────────┴──────────┐
│     credentials_non_expired │   │    │    user_roles      │
│     created_at  TIMESTAMP   │   │    │ ────────────────── │
│     updated_at  TIMESTAMP   │   ├──▶│ FK  user_id        │
│     last_login  TIMESTAMP   │       │ FK  role_id ───────┘
└────────────────────────────┘       │ PK (user_id, role_id)│
                                      └─────────────────────┘

┌────────────────────────────────────┐    ┌────────────────────────────────┐
│       SPRING_SESSION               │    │    SPRING_SESSION_ATTRIBUTES   │
│ ──────────────────────────────── │    │ ──────────────────────────── │
│ PK  PRIMARY_ID      CHAR(36)     │◄───│ FK  SESSION_PRIMARY_ID CHAR(36)│
│ UQ  SESSION_ID      CHAR(36)     │    │     ATTRIBUTE_NAME   VARCHAR   │
│     CREATION_TIME   BIGINT       │    │     ATTRIBUTE_BYTES  BYTEA     │
│     LAST_ACCESSED_TIME BIGINT    │    │ PK (SESSION_PRIMARY_ID,        │
│     MAX_INACTIVE_INTERVAL INT    │    │     ATTRIBUTE_NAME)            │
│     EXPIRY_TIME     BIGINT       │    │                                │
│     PRINCIPAL_NAME  VARCHAR(100) │    │ Stores:                        │
└────────────────────────────────────┘    │ • userId, username, roles     │
                                          │ • DPOP_PUBLIC_KEY (JWK JSON)  │
                                          │ • DPOP_JWK_THUMBPRINT         │
                                          │ • SPRING_SECURITY_CONTEXT     │
                                          └────────────────────────────────┘
```

---

## 9. Technology Stack Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                         APPLICATION                                 │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Spring Boot 4.0.3                                             │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐ │ │
│  │  │ Spring       │ │ Spring       │ │ Spring Session JDBC    │ │ │
│  │  │ Security 7.x │ │ Data JPA    │ │ (DB-backed sessions)   │ │ │
│  │  └──────────────┘ └──────────────┘ └────────────────────────┘ │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐ │ │
│  │  │ Spring MVC   │ │ Spring       │ │ Spring Boot Actuator   │ │ │
│  │  │ + Validation │ │ Boot Web    │ │ (health endpoints)     │ │ │
│  │  └──────────────┘ └──────────────┘ └────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Security Libraries                                            │ │
│  │  ┌──────────────────────┐ ┌──────────────────────────────────┐│ │
│  │  │ Nimbus JOSE JWT      │ │ Caffeine Cache                   ││ │
│  │  │ 10.0.2               │ │ (DPoP replay protection)         ││ │
│  │  │ • DPoP proof parsing │ │ • 100K max entries               ││ │
│  │  │ • ES256 verification │ │ • 300s TTL per jti               ││ │
│  │  │ • JWK thumbprint     │ └──────────────────────────────────┘│ │
│  │  └──────────────────────┘                                      │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Build & Runtime                                               │ │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌────────────────────┐ │ │
│  │  │ Java 21 │ │ Maven   │ │ Lombok   │ │ PostgreSQL Driver  │ │ │
│  │  └─────────┘ └─────────┘ └──────────┘ └────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                         DATABASE                                    │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  PostgreSQL (localhost:5432 / secureapp_db)                    │ │
│  │  • HikariCP connection pool (5-10 connections)                │ │
│  │  • Hibernate dialect: PostgreSQLDialect                       │ │
│  │  • DDL auto: update                                            │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Security Headers Response Anatomy

```
HTTP/1.1 200 OK

┌── Spring Security ──────────────────────────────────────────────────────────┐
│ Content-Security-Policy: default-src 'self'; script-src 'self';            │
│                          style-src 'self' 'unsafe-inline';                 │
│                          img-src 'self' data:; font-src 'self';            │
│                          connect-src 'self'                                │
│ X-Frame-Options: DENY                                                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌── SecurityHeadersFilter ────────────────────────────────────────────────────┐
│ Content-Security-Policy: default-src 'self'; script-src 'self'; ...        │
│                          frame-ancestors 'none'; base-uri 'self';          │
│                          form-action 'self'                                │
│ X-Frame-Options: DENY                                                      │
│ X-Content-Type-Options: nosniff                                            │
│ Strict-Transport-Security: max-age=31536000; includeSubDomains; preload    │
│ X-XSS-Protection: 1; mode=block                                           │
│ Referrer-Policy: strict-origin-when-cross-origin                           │
│ Permissions-Policy: accelerometer=(), camera=(), geolocation=(),           │
│                     gyroscope=(), magnetometer=(), microphone=(),           │
│                     payment=(), usb=()                                     │
│ Cache-Control: no-store, no-cache, must-revalidate, max-age=0              │
│ Pragma: no-cache                                                           │
│ Expires: 0                                                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌── Session Cookie ───────────────────────────────────────────────────────────┐
│ Set-Cookie: JSESSIONID=<uuid>;                                             │
│             Path=/;                                                        │
│             HttpOnly;          ← Not accessible via JavaScript             │
│             Secure;            ← Only sent over HTTPS                      │
│             SameSite=Strict;   ← Not sent on cross-site requests           │
│             Max-Age=900        ← 15 minutes                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌── CSRF Cookie ──────────────────────────────────────────────────────────────┐
│ Set-Cookie: XSRF-TOKEN=<token>;                                            │
│             Path=/;                                                        │
│             (HttpOnly=false)   ← Readable by JavaScript for AJAX requests  │
└─────────────────────────────────────────────────────────────────────────────┘

Content-Type: application/json
Body: { "success": true, "message": "...", "data": {...}, "statusCode": 200 }
```
