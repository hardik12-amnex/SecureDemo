# SecureApp — System Architecture Diagram

> **Version:** 2.0.0 (Stateless JWT + HttpOnly Cookie) | **Spring Boot:** 4.0.3 | **Java:** 21 | **Date:** March 17, 2026

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
│   │   │ • Store private  │   │   private key    │   │ • Attach Bearer │    │   │
│   │   │   key in memory  │   │ • Fresh jti/iat  │   │   cookie (auto) │    │   │
│   │   └──────────────────┘   └──────────────────┘   └────────┬───────┘    │   │
│   │                                                           │            │   │
│   └───────────────────────────────────────────────────────────┼────────────┘   │
│                                                               │                 │
└───────────────────────────────────────────────────────────────┼─────────────────┘
                                                                │
                      HTTPS (Port 8080)                         │
                      Cookie: ACCESS_TOKEN=<jwt> (HttpOnly)     │
                      Header: DPoP: <signed-jwt>                │
                                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          SERVER LAYER (Spring Boot 4.0.3)                        │
│                          Context Path: /api                                     │
│                          Session Policy: STATELESS (no server-side sessions)    │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    SECURITY FILTER CHAIN                                │   │
│   │                    (See Section 2 for details)                          │   │
│   └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │                                           │
│   ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│   │                    MVC INTERCEPTOR CHAIN                                │   │
│   │                    AuthorizationInterceptor                             │   │
│   └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │                                           │
│   ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│   │                    CONTROLLER LAYER                                     │   │
│   │    AuthController          DashboardController                          │   │
│   └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │                                           │
│   ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│   │                    SERVICE LAYER                                        │   │
│   │    AuthService         JwtTokenService         DPoPSessionBindingService│   │
│   └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │                                           │
│   ┌─────────────────────────────────▼───────────────────────────────────────┐   │
│   │                    REPOSITORY / DATA LAYER                              │   │
│   │    UserRepository          RoleRepository                               │   │
│   └─────────────────────────────────┬───────────────────────────────────────┘   │
│                                     │                                           │
└─────────────────────────────────────┼───────────────────────────────────────────┘
                                      │
                                      │  JDBC
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          DATA LAYER (PostgreSQL :5432)                           │
│                          Database: secureapp_db                                 │
│                                                                                 │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                         │
│   │    users      │  │    roles     │  │  user_roles   │                         │
│   │  ──────────── │  │  ────────── │  │  ──────────── │                         │
│   │ id           │  │ id           │  │ user_id  (FK) │                         │
│   │ username     │  │ name         │  │ role_id  (FK) │                         │
│   │ email        │  │ description  │  └──────────────┘                         │
│   │ password     │  │ created_at   │                                            │
│   │  (BCrypt-12) │  │ updated_at   │  No session tables needed!                │
│   │ first_name   │  └──────────────┘  (Stateless JWT architecture)             │
│   │ last_name    │                                                              │
│   │ enabled      │                                                              │
│   │ created_at   │                                                              │
│   │ last_login   │                                                              │
│   └──────────────┘                                                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Filter Chain — Detailed Request Pipeline

```
                            ┌──────────────────┐
                            │  INCOMING REQUEST │
                            │  GET /api/dashboard│
                            │  Cookie:           │
                            │    ACCESS_TOKEN=jwt│
                            │  DPoP: <proof-jwt> │
                            └────────┬───────────┘
                                     │
              ┌──────────────────────▼──────────────────────┐
              │          ① CORS Filter (Spring)             │
              │  ──────────────────────────────────────────  │
              │  • Validates Origin: http://localhost:4200   │
              │  • Handles preflight OPTIONS requests        │
              │  • Exposes DPoP & Authorization headers      │
              │  ✗ Origin not allowed → 403 Forbidden        │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ CORS OK
              ┌──────────────────────▼──────────────────────┐
              │          CSRF Filter (Spring)               │
              │  ──────────────────────────────────────────  │
              │  • CookieCsrfTokenRepository (HttpOnly=off) │
              │  • Validates X-XSRF-TOKEN on POST/PUT/DELETE │
              │  • GET requests skip CSRF check              │
              │  • Public endpoints excluded                 │
              │  ✗ Missing/invalid CSRF → 403 Forbidden      │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ CSRF OK
              ┌──────────────────────▼──────────────────────┐
              │     ② JwtAuthenticationFilter [CUSTOM]      │
              │  ──────────────────────────────────────────  │
              │  Excluded: /auth/login, /auth/register,     │
              │            /auth/logout, /health             │
              │                                              │
              │  Step 1: Extract JWT from ACCESS_TOKEN cookie│
              │  Step 2: Validate JWT signature (HMAC-SHA512)│
              │  Step 3: Validate expiry and issuer          │
              │  Step 4: Extract sub, roles, userId, dpop_jkt│
              │  Step 5: Set Authentication in SecurityContext│
              │  Step 6: Store dpop_jkt as request attribute │
              │  ✗ Any failure → 401 JSON response           │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ JWT Valid
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
              │  Step 8: Compare JWK thumbprint vs JWT-bound │
              │          dpop_jkt (from request attribute)   │
              │  ✗ Any failure → 401 JSON response           │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ DPoP Valid
              ┌──────────────────────▼──────────────────────┐
              │     ④ SecurityHeadersFilter [CUSTOM]        │
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
              │     ⑤ Spring Security Authorization         │
              │  ──────────────────────────────────────────  │
              │  .authorizeHttpRequests:                      │
              │    /auth/login, /auth/register → permitAll() │
              │    /auth/logout, /health      → permitAll() │
              │    /** (everything else)       → authenticated│
              │  ✗ Not authenticated → 401                   │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Authenticated
        ═════════════════════════════╪═══════════════════════════
                  FILTER CHAIN END │  MVC INTERCEPTOR CHAIN START
        ═════════════════════════════╪═══════════════════════════
              ┌──────────────────────▼──────────────────────┐
              │     ⑥ AuthorizationInterceptor [CUSTOM]     │
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
              │     ⑦ @PreAuthorize (Method Security)       │
              │  ──────────────────────────────────────────  │
              │  • @PreAuthorize("isAuthenticated()")        │
              │  • @PreAuthorize("hasRole('ADMIN')")         │
              │  ✗ Access denied → 403                       │
              └──────────────────────┬──────────────────────┘
                                     │ ✓ Authorized
              ┌──────────────────────▼──────────────────────┐
              │          ⑧ CONTROLLER METHOD                │
              │  ──────────────────────────────────────────  │
              │  • Process business logic                    │
              │  • Return ApiResponse<T> JSON                │
              └──────────────────────┬──────────────────────┘
                                     │
                            ┌────────▼───────────┐
                            │  HTTP RESPONSE      │
                            │  200 OK / JSON body  │
                            │  + Security headers  │
                            └──────────────────────┘
```

---

## 3. Login Flow — DPoP Key Binding & JWT Token Generation

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
     │                    │  c. DPoP VALIDATION (stateless)                   │
     │                    │     DPoPSessionBindingService                     │
     │                    │     .validateAndGetThumbprint(proof, method, uri) │
     │                    │     → DPoPProofValidator.validate(proof)          │
     │                    │       → Parse JWT                                │
     │                    │       → Verify typ = dpop+jwt                    │
     │                    │       → Verify alg = ES256                       │
     │                    │       → Extract JWK public key                   │
     │                    │       → Verify signature with public key         │
     │                    │       → Validate htm, htu, iat, jti              │
     │                    │       → Compute JWK Thumbprint                   │
     │                    │     → Return thumbprint (no session storage)      │
     │                    │                                                   │
     │                    │  d. JWT TOKEN GENERATION                          │
     │                    │     JwtTokenService.generateToken(                │
     │                    │       userDetails, userId, dpopThumbprint)        │
     │                    │     → Build JWT with claims:                      │
     │                    │       sub = username                              │
     │                    │       roles = [ROLE_USER]                         │
     │                    │       userId = 2                                  │
     │                    │       dpop_jkt = <thumbprint>                     │
     │                    │       iss = "secureapp"                           │
     │                    │       exp = now + 15 min                          │
     │                    │     → Sign with HMAC-SHA512                       │
     │                    │     → Return compact JWT string                   │
     │                    └───────────────────────────────────────────────────┘
     │                                                    │
     │ ◀────────────────────────────────────────────────── │
     │  200 OK                                            │
     │  Set-Cookie: ACCESS_TOKEN=<jwt>;                   │
     │              Path=/; HttpOnly; Secure;              │
     │              SameSite=Strict; Max-Age=900           │
     │  Body: {                                           │
     │    "success": true,                                │
     │    "message": "Login successful",                  │
     │    "data": {                                       │
     │      "expiresIn": 900000,                         │
     │      "user": { id, username, email, roles, ... }  │
     │    }                                               │
     │  }                                                 │
     │  (JWT is NOT in body — it's in the HttpOnly cookie)│
     │                                                    │
     │  ┌─────────────────────────────────────────────┐   │
     │  │ 4. Client stores:                           │   │
     │  │    • ACCESS_TOKEN cookie (automatic by       │   │
     │  │      browser — HttpOnly, inaccessible to JS) │   │
     │  │    • privateKey in memory (for future proofs)│   │
     │  └─────────────────────────────────────────────┘   │
     │                                                    │
```

---

## 4. Authenticated Request Flow — JWT + DPoP Verification

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
     │  Cookie: ACCESS_TOKEN=eyJhbGciOiJIUzUxMiJ9...    │
     │  DPoP: eyJhbGciOi....<new-signed-jwt>              │
     │ ──────────────────────────────────────────────────▶ │
     │                                                    │
     │                    ┌───────────────────────────────────────────────────┐
     │                    │                                                   │
     │                    │  ② JwtAuthenticationFilter                        │
     │                    │  ├── Extract JWT from ACCESS_TOKEN cookie         │
     │                    │  ├── Validate JWT signature (HMAC-SHA512)         │
     │                    │  ├── Validate expiry and issuer                   │
     │                    │  ├── Extract sub="testuser", roles=[ROLE_USER]    │
     │                    │  ├── Extract dpop_jkt=<thumbprint>               │
     │                    │  ├── Set Authentication in SecurityContext        │
     │                    │  └── Store dpop_jkt as request attribute          │
     │                    │      ✓ JWT Valid → continue chain                 │
     │                    │                                                   │
     │                    │  ③ DPoPAuthenticationFilter                       │
     │                    │  ├── Extract DPoP header                          │
     │                    │  ├── Parse JWT, verify ES256 signature            │
     │                    │  ├── Validate htm="GET", htu matches URL          │
     │                    │  ├── Validate iat within ±300s                    │
     │                    │  ├── Check jti not in Caffeine cache (replay)     │
     │                    │  ├── Get dpop_jkt from request attribute          │
     │                    │  └── Compare proof thumbprint == JWT thumbprint   │
     │                    │      ✓ Match → continue chain                     │
     │                    │      ✗ Mismatch → 401 "key does not match"        │
     │                    │                                                   │
     │                    │  ⑥ AuthorizationInterceptor                      │
     │                    │  ├── Path: /dashboard                             │
     │                    │  ├── Allowed: [ROLE_USER, ROLE_ADMIN]             │
     │                    │  ├── User roles: [ROLE_USER]                      │
     │                    │  └── ROLE_USER ∈ allowed? YES                     │
     │                    │      ✓ Authorized → continue                      │
     │                    │                                                   │
     │                    │  ⑧ DashboardController.dashboard()                │
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
│  ┌──────────────────┐  ┌──────────────────────────┐                        │
│  │  SecurityConfig   │  │     WebMvcConfig         │                        │
│  │  ────────────────│  │  ────────────────────── │                        │
│  │ • Filter chain   │  │ • Registers             │                        │
│  │ • CORS config    │  │   AuthorizationInter-   │                        │
│  │ • CSRF disabled  │  │   ceptor                │                        │
│  │ • STATELESS      │  │ • Exclude paths:        │                        │
│  │   sessions       │  │   /auth/*, /health      │                        │
│  │ • Auth rules     │  └──────────┬───────────────┘                        │
│  │ • Header config  │             │                                        │
│  └────────┬─────────┘             │ registers                              │
│           │ registers             ▼                                        │
│           ▼                                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         FILTER / INTERCEPTOR LAYER                   │  │
│  │                                                                      │  │
│  │  ┌──────────────────────┐  ┌─────────────────────┐                  │  │
│  │  │JwtAuthentication-    │  │DPoPAuthentication-   │                  │  │
│  │  │    Filter             │  │    Filter             │                  │  │
│  │  │ ──────────────────── │  │ ───────────────────  │                  │  │
│  │  │ • OncePerRequest     │  │ • OncePerRequest    │                  │  │
│  │  │ • Before UsernameP.. │  │ • After JWT filter  │                  │  │
│  │  │ ─────────────────    │  │ ────────────────    │                  │  │
│  │  │ Uses:                │  │ Uses:               │                  │  │
│  │  │ • JwtTokenService    │  │ • DPoPProofValidator │                  │  │
│  │  │ Sets:                │  │ • DPoPReplayProtect..│                  │  │
│  │  │ • SecurityContext    │  │ • Request attribute  │                  │  │
│  │  │ • Request attributes │  │   (dpop_jkt)        │                  │  │
│  │  └──────────┬───────────┘  └─────────────────────┘                  │  │
│  │             │                                                        │  │
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
│                          SECURITY / JWT / DPoP LAYER                         │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐  │
│  │  JwtTokenService       │  │  DPoPProofValidator                        │  │
│  │  ──────────────────── │  │  ──────────────────────────────────────── │  │
│  │  • Generate JWT        │  │  • Parse JWT                              │  │
│  │  • Sign HMAC-SHA512    │  │  • Verify typ, alg                        │  │
│  │  • Validate token      │  │  • Verify ES256 sig                       │  │
│  │  • Extract claims      │  │  • Validate htm, htu                      │  │
│  │  • Embed dpop_jkt      │  │  • Validate iat, jti                      │  │
│  └────────────────────────┘  │  • Compute thumbprint                     │  │
│                              └────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐  │
│  │DPoPSessionBindingService│  │DPoPReplayProtection-                      │  │
│  │ ──────────────────── │  │    Service                                │  │
│  │ • Called at login      │  │ ──────────────────────────────────────── │  │
│  │ • Validates proof      │  │ • Caffeine cache                        │  │
│  │ • Returns thumbprint   │  │ • 100K entries max                      │  │
│  │   (for JWT embedding)  │  │ • 300s TTL per jti                      │  │
│  └────────────────────────┘  │ • isJtiUnique(jti)                      │  │
│                              └────────────────────────────────────────────┘  │
│                                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────────────────────┐  │
│  │DPoPValidationException │  │  DPoPConstants                            │  │
│  │ → thrown → 401         │  │  • DPOP_HEADER, TOKEN_TYPE, claims        │  │
│  └────────────────────────┘  │  • TOKEN_CLAIM_DPOP_JKT                   │  │
│                              │  • MAX_PROOF_AGE = 300s                    │  │
│                              └────────────────────────────────────────────┘  │
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
│  │  • AuthService               │  │  • SecurityUtils (SecurityContext)   │  │
│  │  • DPoPSessionBindingService │  └──────────────────────────────────────┘  │
│  │  • JwtTokenService           │                                            │
│  └──────────────────────────────┘                                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. DPoP Proof-of-Possession — Attack Prevention Model

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   ATTACK SCENARIOS & DPoP PROTECTION                     │
└──────────────────────────────────────────────────────────────────────────┘

  SCENARIO 1: JWT Token Theft via XSS
  ─────────────────────────────────────
  
    Attacker injects JavaScript to steal the JWT token.
    
    ✗ BLOCKED at the browser level!
    The JWT is in an HttpOnly cookie — JavaScript cannot read it.
    Even successful XSS cannot extract the token.
    
    If attacker somehow intercepts the cookie (e.g., network):
    Attacker sends:  GET /api/dashboard
                     Cookie: ACCESS_TOKEN=<stolen-jwt>
                     (no DPoP header)
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       "Missing DPoP proof header" → 401
    
    ┌─────────────────────────────────────────────┐
    │ 1. HttpOnly cookie prevents XSS token theft. │
    │ 2. Even with the cookie, the attacker cannot │
    │    forge a DPoP proof because they don't have│
    │    the client's ECDSA private key (which never│
    │    leaves the browser's memory).              │
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


  SCENARIO 3: Attacker's Key + Stolen JWT Token
  ──────────────────────────────────────────────
  
    Attacker has their OWN keypair and a stolen JWT token.
    Attacker generates a valid DPoP proof with THEIR key.
    
    ③ DPoPAuthenticationFilter → ✗ BLOCKED
       Step 8: JWK thumbprint mismatch
       Proof thumbprint ≠ JWT-bound dpop_jkt
       "DPoP proof key does not match token-bound key" → 401
    
    ┌─────────────────────────────────────────────┐
    │ The public key thumbprint is embedded in the │
    │ JWT token (dpop_jkt claim) at login time.    │
    │ A different key produces a different          │
    │ thumbprint → mismatch → rejected.            │
    └─────────────────────────────────────────────┘


  SCENARIO 4: JWT Token Tampering (Change Roles)
  ───────────────────────────────────────────────
  
    Attacker modifies JWT claims to escalate privileges.
    (e.g., change roles from ROLE_USER to ROLE_ADMIN)
    
    ② JwtAuthenticationFilter → ✗ BLOCKED
       HMAC-SHA512 signature verification fails
       "Invalid or expired token" → 401
    
    ┌─────────────────────────────────────────────┐
    │ Any modification to the JWT payload          │
    │ invalidates the HMAC-SHA512 signature.       │
    │ The server detects tampering immediately.    │
    └─────────────────────────────────────────────┘


  SCENARIO 5: Expired / Stale DPoP Proof
  ───────────────────────────────────────
  
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

## 7. Entity-Relationship Diagram

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
│     account_non_expired     │   │    ┌────────┴──────────┐
│     account_non_locked      │   │    │    user_roles      │
│     credentials_non_expired │   │    │ ────────────────── │
│     created_at  TIMESTAMP   │   ├──▶│ FK  user_id        │
│     updated_at  TIMESTAMP   │       │ FK  role_id ───────┘
│     last_login  TIMESTAMP   │       │ PK (user_id, role_id)│
└────────────────────────────┘       └─────────────────────┘

No session tables needed — stateless JWT architecture!
```

---

## 8. Technology Stack Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                         APPLICATION                                 │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Spring Boot 4.0.3                                             │ │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐ │ │
│  │  │ Spring       │ │ Spring       │ │ JJWT 0.12.6            │ │ │
│  │  │ Security 7.x │ │ Data JPA    │ │ (JWT generation &      │ │ │
│  │  │ (STATELESS)  │ └──────────────┘ │  validation, HS512)    │ │ │
│  │  └──────────────┘                  └────────────────────────┘ │ │
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
│  │  • Tables: users, roles, user_roles (NO session tables)       │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Security Headers Response Anatomy

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

┌── JWT HttpOnly Cookie ──────────────────────────────────────────────────────┐
│ Set-Cookie: ACCESS_TOKEN=<jwt>;                                            │
│             Path=/;                                                        │
│             HttpOnly;          ← NOT accessible via JavaScript (XSS-proof) │
│             Secure;            ← Only sent over HTTPS                      │
│             SameSite=Strict;   ← Never sent on cross-site requests         │
│             Max-Age=900        ← 15 minutes (matches JWT expiry)           │
└─────────────────────────────────────────────────────────────────────────────┘

┌── CSRF Cookie ──────────────────────────────────────────────────────────────┐
│ Set-Cookie: XSRF-TOKEN=<token>;                                            │
│             Path=/;                                                        │
│             (HttpOnly=false)   ← Readable by JavaScript for AJAX requests  │
└─────────────────────────────────────────────────────────────────────────────┘

┌── Authentication Headers (sent by client) ──────────────────────────────────┐
│   Cookie: ACCESS_TOKEN=<jwt>   (auto-attached by browser)                  │
│   DPoP: <fresh-dpop-proof-jwt> (manually attached by client JS)            │
│   X-XSRF-TOKEN: <csrf-token>  (for POST/PUT/DELETE requests)              │
└─────────────────────────────────────────────────────────────────────────────┘

Content-Type: application/json
Body: { "success": true, "message": "...", "data": {...}, "statusCode": 200 }
```
