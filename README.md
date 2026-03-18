# SecureApp — Enterprise-Grade Spring Boot Security Backend

**Version:** 2.0.0 (Stateless JWT + HttpOnly Cookie)  
**Java:** 21  
**Spring Boot:** 4.0.3  
**Last Updated:** March 17, 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Technology Stack](#technology-stack)
3. [Architecture](#architecture)
4. [Project Structure](#project-structure)
5. [Security Features](#security-features)
6. [DPoP (Demonstration of Proof-of-Possession)](#dpop-demonstration-of-proof-of-possession)
7. [Request Flow](#request-flow)
8. [API Reference](#api-reference)
9. [Role-Based Access Control](#role-based-access-control)
10. [Database Setup](#database-setup)
11. [Configuration](#configuration)
12. [Running the Application](#running-the-application)
13. [Default Test Credentials](#default-test-credentials)

---

## Overview

SecureApp is a production-grade Spring Boot backend demonstrating enterprise security best practices. It implements **stateless JWT-based authentication** with **DPoP (Demonstration of Proof-of-Possession)** binding, **role-based access control**, and comprehensive **security headers**.

The application is **fully stateless** — no server-side sessions are used. The JWT access token is transported in an **HttpOnly, Secure, SameSite=Strict** cookie, making it completely inaccessible to JavaScript (XSS-proof). The browser automatically attaches the cookie on every request. CSRF protection is enabled via `CookieCsrfTokenRepository`. DPoP ensures that even if the cookie/token is somehow intercepted, the attacker cannot use it without possessing the client's private cryptographic key.

---

## Technology Stack

| Component             | Technology                          |
|-----------------------|-------------------------------------|
| Language              | Java 21                             |
| Framework             | Spring Boot 4.0.3                   |
| Security              | Spring Security 7.x                 |
| Authentication        | JWT (JJWT 0.12.6) — Stateless      |
| Database              | PostgreSQL                          |
| DPoP Proof Validation | Nimbus JOSE JWT 10.0.2              |
| Replay Protection     | Caffeine Cache (in-memory)          |
| Build Tool            | Maven                               |
| Code Generation       | Lombok                              |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT (Browser / Angular)                   │
│  1. Generate ECDSA P-256 keypair (WebCrypto)                       │
│  2. Build DPoP proof JWT (self-signed with private key)             │
│  3. Send request with DPoP header + Authorization: Bearer <JWT>     │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      SPRING SECURITY FILTER CHAIN                    │
│                                                                      │
│  ┌──────────────────────────┐                                        │
│  │ JwtAuthenticationFilter  │ ← Validates JWT token (signature,      │
│  │  • Parse Bearer token     │   expiry, issuer). Sets SecurityContext│
│  │  • Extract user + roles   │   Stores dpop_jkt as request attribute│
│  │  • Set SecurityContext    │   Returns 401 if invalid              │
│  └───────────┬──────────────┘                                        │
│              ▼                                                       │
│  ┌──────────────────────────┐                                        │
│  │ DPoPAuthenticationFilter │ ← Validates DPoP proof JWT             │
│  │  • Parse & verify JWT     │   Checks JWK thumbprint vs JWT-bound  │
│  │  • Replay protection (jti)│   thumbprint. Returns 401 if mismatch │
│  └───────────┬──────────────┘                                        │
│              ▼                                                       │
│  ┌──────────────────────────┐                                        │
│  │ SecurityHeadersFilter    │ ← Adds CSP, HSTS, X-Frame-Options     │
│  └───────────┬──────────────┘                                        │
└──────────────┼───────────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     SPRING MVC INTERCEPTOR CHAIN                     │
│                                                                      │
│  ┌──────────────────────────┐                                        │
│  │ AuthorizationInterceptor │ ← Role-based path authorization        │
│  │  • /admin/** → ROLE_ADMIN │   Uses RolePermissionMapping           │
│  │  • /dashboard/** → USER+  │   Returns 403 if denied               │
│  └───────────┬──────────────┘                                        │
└──────────────┼───────────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          CONTROLLERS                                 │
│  AuthController    → /auth/login, /auth/register, /auth/logout,      │
│                      /auth/me                                        │
│  DashboardController → /health, /dashboard, /admin/users             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
src/main/java/com/example/secureapp/
├── SecureAppApplication.java              # Spring Boot entry point
├── config/
│   ├── SecurityConfig.java                # Spring Security filter chain, CORS, stateless session
│   └── WebMvcConfig.java                  # Registers AuthorizationInterceptor
├── controller/
│   ├── AuthController.java                # Login (with DPoP + JWT), register, logout, /auth/me
│   └── DashboardController.java           # /health, /dashboard, /admin/users
├── dpop/
│   ├── DPoPAuthenticationFilter.java      # Filter: validates DPoP proof on every authenticated request
│   ├── DPoPConstants.java                 # Header names, claim keys, cache config constants
│   ├── DPoPProofValidator.java            # Parses & validates DPoP proof JWT (RFC 9449)
│   ├── DPoPReplayProtectionService.java   # Caffeine cache for jti replay protection
│   ├── DPoPSessionBindingService.java     # Validates DPoP proof at login, returns thumbprint for JWT
│   └── DPoPValidationException.java       # Thrown when DPoP proof fails validation
├── dto/
│   ├── ApiResponse.java                   # Standard response wrapper {success, message, data, statusCode}
│   ├── LoginRequest.java                  # Login DTO {username, password}
│   ├── LoginResponse.java                # Login response with JWT token {accessToken, tokenType, expiresIn, user}
│   ├── SignUpRequest.java                 # Registration DTO with validation
│   └── UserResponse.java                 # User response DTO
├── entity/
│   ├── Role.java                          # JPA entity: roles table
│   └── User.java                          # JPA entity: users table (ManyToMany → roles)
├── exception/
│   ├── BadRequestException.java           # 400 Bad Request
│   ├── GlobalExceptionHandler.java        # @RestControllerAdvice — centralized error handling
│   └── ResourceNotFoundException.java     # 404 Not Found
├── filter/
│   ├── JwtAuthenticationFilter.java       # Validates JWT token, sets SecurityContext (replaces SessionValidationFilter)
│   └── SecurityHeadersFilter.java         # Adds CSP, HSTS, X-Frame-Options, etc.
├── repository/
│   ├── RoleRepository.java                # JPA repository for Role
│   └── UserRepository.java               # JPA repository for User
├── security/
│   ├── AuthorizationInterceptor.java      # MVC interceptor: role-based path authorization
│   ├── CustomUserDetailsService.java      # Loads UserDetails from DB for Spring Security
│   ├── JwtTokenService.java              # JWT token generation, validation, claims extraction
│   └── RolePermissionMapping.java         # Centralized path → allowed-roles mapping
├── service/
│   └── AuthService.java                   # Business logic: register, login, getUserById
└── util/
    ├── SecurityUtil.java                  # Client IP detection, secure connection check
    └── SecurityUtils.java                 # Static: getCurrentUser(), getCurrentUserRoles(), hasRole()
```

---

## Security Features

### 1. Stateless JWT-Based Authentication (HttpOnly Cookie)
- JWT access tokens issued at login, signed with HMAC-SHA512
- Token contains user identity (sub), roles, userId, and DPoP binding (dpop_jkt)
- JWT transported in **HttpOnly, Secure, SameSite=Strict** cookie (`ACCESS_TOKEN`)
  - **HttpOnly** — inaccessible to JavaScript, preventing XSS token theft
  - **Secure** — only transmitted over HTTPS
  - **SameSite=Strict** — never sent on cross-site requests
- 15-minute token expiration (configurable)
- No server-side sessions — fully stateless and horizontally scalable
- Browser automatically attaches the cookie on every request

### 2. DPoP (Demonstration of Proof-of-Possession) — RFC 9449
- Client generates an ECDSA P-256 keypair locally (browser WebCrypto API)
- At login, client sends a self-signed DPoP proof JWT with the public key embedded
- Server validates the proof and embeds the JWK thumbprint in the JWT access token (`dpop_jkt` claim)
- Every subsequent request must include a fresh DPoP proof signed by the same private key
- JWK thumbprint comparison prevents stolen JWT tokens from being useful

### 3. CSRF Protection
- Enabled via `CookieCsrfTokenRepository` (cookie-based, `HttpOnly=false` for JS read)
- Required because the JWT is transported in an HttpOnly cookie that browsers auto-attach
- All state-changing requests (POST, PUT, DELETE, PATCH) require a valid `X-XSRF-TOKEN` header
- Public endpoints (`/auth/login`, `/auth/register`, `/auth/logout`, `/health`) are excluded

### 4. CORS
- Allowed origin: `http://localhost:4200` (Angular dev server)
- Credentials allowed (cookies, auth headers)
- Preflight cache: 3600 seconds

### 5. Security Headers (SecurityHeadersFilter)
| Header                    | Value                                                     |
|---------------------------|-----------------------------------------------------------|
| Content-Security-Policy   | `default-src 'self'; script-src 'self'; ...`              |
| X-Frame-Options           | `DENY`                                                    |
| X-Content-Type-Options    | `nosniff`                                                 |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload`            |
| X-XSS-Protection          | `1; mode=block`                                           |
| Referrer-Policy           | `strict-origin-when-cross-origin`                         |
| Permissions-Policy        | `accelerometer=(), camera=(), geolocation=(), ...`        |
| Cache-Control             | `no-store, no-cache, must-revalidate, max-age=0`         |

### 6. Role-Based Access Control (AuthorizationInterceptor + RolePermissionMapping)
Every request passes through a Spring MVC interceptor that checks the user's roles against a centralized permission map.

### 7. Password Security
- BCrypt with strength 12
- Minimum 8 characters on registration

---

## DPoP (Demonstration of Proof-of-Possession)

### What Problem Does DPoP Solve?
Even with the JWT stored in an HttpOnly cookie (safe from XSS), an attacker who intercepts the cookie via network attacks or CSRF bypass could replay it. DPoP adds a **cryptographic binding** — the client must prove it holds a private key that corresponds to the public key registered at login time and embedded in the JWT token.

### How It Works (Stateless + HttpOnly Cookie)

```
LOGIN FLOW:
1. Client generates ECDSA P-256 keypair (crypto.subtle.generateKey)
2. Client builds a DPoP proof JWT:
   Header: { "typ": "dpop+jwt", "alg": "ES256", "jwk": { <public-key> } }
   Payload: { "htm": "POST", "htu": "http://localhost:8080/api/auth/login",
              "iat": <now>, "jti": "<uuid>" }
3. Client signs the JWT with the private key
4. Client sends: POST /api/auth/login
   Body: { username, password }
   Header: DPoP: <signed-jwt>
5. Server validates credentials → validates DPoP proof → generates JWT token
   with dpop_jkt claim set to the public key's JWK thumbprint
6. Server sets JWT in HttpOnly cookie:
   Set-Cookie: ACCESS_TOKEN=<jwt>; HttpOnly; Secure; SameSite=Strict; Max-Age=900
7. Server returns: { expiresIn: 900000, user: {...} }
   (Token is NOT in the response body — it's in the cookie)

SUBSEQUENT REQUESTS:
1. Client builds a fresh DPoP proof for the target endpoint
2. Client sends request with:
   Cookie: ACCESS_TOKEN=<jwt> (auto-attached by browser)
   DPoP: <new-proof>
3. JwtAuthenticationFilter:
   a. Extracts JWT from ACCESS_TOKEN cookie
   b. Validates JWT token signature, expiry, issuer
   c. Extracts user identity, roles, dpop_jkt claim
   d. Sets SecurityContext with authenticated user
   e. Stores dpop_jkt as request attribute
4. DPoPAuthenticationFilter:
   a. Parses & verifies the DPoP proof JWT signature
   b. Validates htm (HTTP method) and htu (request URI)
   c. Checks iat is within 5-minute window
   d. Checks jti uniqueness (replay protection via Caffeine cache)
   e. Compares JWK thumbprint with JWT-bound thumbprint (dpop_jkt)
   f. If all pass → request proceeds; otherwise → 401
```

### DPoP Proof JWT Structure
```json
{
  "header": {
    "typ": "dpop+jwt",
    "alg": "ES256",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>"
    }
  },
  "payload": {
    "htm": "GET",
    "htu": "http://localhost:8081/api/dashboard",
    "iat": 1741785600,
    "jti": "unique-random-uuid"
  }
}
```

### JWT Access Token Structure
```json
{
  "sub": "testuser",
  "roles": ["ROLE_USER"],
  "userId": 2,
  "dpop_jkt": "<base64url-jwk-thumbprint>",
  "iss": "secureapp",
  "iat": 1741785600,
  "exp": 1741786500
}
```

### Validation Rules (RFC 9449)
| Check                | Rule                                                  |
|----------------------|-------------------------------------------------------|
| `typ`                | Must be `dpop+jwt`                                    |
| `alg`                | Must be `ES256` (ECDSA P-256)                         |
| `jwk`                | Must be an EC public key (no private key material)    |
| Signature            | Verified using the embedded public key                |
| `htm`                | Must match the HTTP method of the current request     |
| `htu`                | Must match the full request URI                       |
| `iat`                | Must be within ±300 seconds of server time            |
| `jti`                | Must be unique (not seen in the replay cache)         |
| JWK Thumbprint       | Must match the thumbprint bound to the JWT token      |

---

## Request Flow

### Public Endpoints (No Authentication Required)
```
POST /api/auth/register   → Create new user account
POST /api/auth/login      → Authenticate + get JWT with DPoP binding
POST /api/auth/logout     → Client discards JWT token
GET  /api/health          → Health check
```

### Protected Endpoints (JWT Cookie + DPoP Required)
```
Request (with ACCESS_TOKEN cookie + DPoP header)
        → JwtAuthenticationFilter → DPoPAuthenticationFilter
        → AuthorizationInterceptor → Controller

GET  /api/auth/me          → Get current authenticated user
GET  /api/dashboard        → Dashboard (ROLE_USER, ROLE_ADMIN)
GET  /api/admin/users      → Admin-only user list (ROLE_ADMIN)
```

---

## API Reference

### Base URL
```
http://localhost:8081/api
```

### Standard Response Format
```json
{
  "success": true,
  "message": "Operation description",
  "data": { ... },
  "statusCode": 200,
  "timestamp": 1741785600000
}
```

### Error Response Format (from filters)
```json
{
  "status": "ERROR",
  "message": "Error description",
  "timestamp": "2026-03-16T10:00:00Z"
}
```

### Endpoints

#### POST /auth/register
Create a new user account with the default `ROLE_USER` role.

**Request Body:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "firstName": "New",
  "lastName": "User",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```

**Validation Rules:**
- `username`: Required, 3–50 characters
- `email`: Required, valid email format
- `firstName`: Required, 2–50 characters
- `lastName`: Required, 2–50 characters
- `password`: Required, 8–128 characters
- `confirmPassword`: Required, must match password

**Response (201):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "id": 3,
    "username": "newuser",
    "email": "newuser@example.com",
    "firstName": "New",
    "lastName": "User",
    "enabled": true,
    "roles": ["ROLE_USER"],
    "createdAt": "2026-03-16T10:00:00",
    "updatedAt": "2026-03-16T10:00:00"
  },
  "statusCode": 201
}
```

#### POST /auth/login
Authenticate the user and set a JWT access token in an HttpOnly cookie with DPoP key binding.

**Required Headers:**
- `Content-Type: application/json`
- `DPoP: <self-signed-dpop-proof-jwt>`

**Request Body:**
```json
{
  "username": "testuser",
  "password": "UserPass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "expiresIn": 900000,
    "user": {
      "id": 2,
      "username": "testuser",
      "email": "test@example.com",
      "firstName": "Test",
      "lastName": "User",
      "enabled": true,
      "roles": ["ROLE_USER"],
      "lastLogin": "2026-03-17T10:00:00"
    }
  },
  "statusCode": 200
}
```

**Response Headers (set by server):**
- `Set-Cookie: ACCESS_TOKEN=<jwt>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900`

> **Note:** The JWT token is NOT in the response body — it is set as an HttpOnly cookie, inaccessible to JavaScript.

#### POST /auth/logout
Logout — clears the JWT HttpOnly cookie.

**Response (200):**
```json
{
  "success": true,
  "message": "Logout successful",
  "data": null,
  "statusCode": 200
}
```

**Response Headers:**
- `Set-Cookie: ACCESS_TOKEN=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`

#### GET /auth/me (Protected)
Get the currently authenticated user's profile.

**Required Headers:**
- `Cookie: ACCESS_TOKEN=<jwt>` (automatically attached by browser)
- `DPoP: <fresh-dpop-proof-jwt>`

#### GET /health (Public)
Health check endpoint — no authentication required.

#### GET /dashboard (Protected — ROLE_USER, ROLE_ADMIN)
Dashboard for authenticated users.

#### GET /admin/users (Protected — ROLE_ADMIN only)
Admin-only endpoint.

---

## Role-Based Access Control

### Permission Matrix (RolePermissionMapping)

| Path Pattern           | ROLE_USER | ROLE_ADMIN | Notes                          |
|------------------------|-----------|------------|--------------------------------|
| `/auth/login`          | Public    | Public     | No auth required               |
| `/auth/register`       | Public    | Public     | No auth required               |
| `/auth/logout`         | Public    | Public     | No auth required               |
| `/health`              | Public    | Public     | No auth required               |
| `/dashboard/**`        | ✅        | ✅         | Any authenticated user         |
| `/admin/**`            | ❌        | ✅         | Admin only                     |
| `/activity/admin/**`   | ❌        | ✅         | Admin only                     |
| `/activity/profile/**` | ✅        | ✅         | User + Admin                   |
| `/activity/action/**`  | ✅        | ✅         | User + Admin                   |
| All other paths        | ✅*       | ✅*        | *Requires authentication only  |

### Authorization Enforcement Layers
1. **Spring Security** (`SecurityConfig`) — `.authorizeHttpRequests()` enforces authentication
2. **JwtAuthenticationFilter** — Validates JWT token and sets SecurityContext
3. **DPoPAuthenticationFilter** — Validates cryptographic proof-of-possession
4. **AuthorizationInterceptor** — Role-based path authorization via `RolePermissionMapping`
5. **`@PreAuthorize`** — Method-level security on controller methods

---

## Database Setup

### Prerequisites
- PostgreSQL server running on `localhost:5432`
- Database: `secureapp_db`
- User: `postgres` / Password: `postgres`

### Initialize Database
```sql
-- Create the database
CREATE DATABASE secureapp_db;

-- Connect and run the init script
\c secureapp_db
\i init-database.sql
```

Or run the SQL script directly:
```bash
psql -U postgres -d secureapp_db -f init-database.sql
```

### Tables Created
| Table                       | Purpose                                         |
|-----------------------------|--------------------------------------------------|
| `roles`                     | Role definitions (ROLE_USER, ROLE_ADMIN, etc.)   |
| `users`                     | User accounts with credentials and profile data  |
| `user_roles`                | Many-to-many junction table for user ↔ role      |

> **Note:** No session tables are needed. The application is fully stateless — authentication state is carried in JWT tokens.

---

## Configuration

### Key Properties (`application.properties`)

| Property                                    | Value                   | Description                              |
|---------------------------------------------|-------------------------|------------------------------------------|
| `server.port`                               | `8081`                  | Application port                         |
| `server.servlet.context-path`               | `/api`                  | All URLs prefixed with `/api`            |
| `app.security.jwt.secret`                   | (base64 key)            | HMAC-SHA512 signing key                  |
| `app.security.jwt.expiration-ms`            | `900000`                | JWT token expiry (15 min)                |
| `app.security.jwt.issuer`                   | `secureapp`             | JWT issuer claim                         |
| `spring.jpa.hibernate.ddl-auto`             | `update`                | Auto-update schema                       |
| `app.security.dpop.max-proof-age-seconds`   | `300`                   | DPoP proof validity window (5 min)       |
| `app.security.dpop.jti-cache-max-size`      | `100000`                | Max entries in JTI replay cache          |

---

## Running the Application

### Prerequisites
1. Java 21 installed
2. Maven installed
3. PostgreSQL running with `secureapp_db` database created
4. Run `init-database.sql` to create tables and seed data

### Build & Run
```bash
# Build
mvn clean compile

# Run
mvn spring-boot:run

# Or build JAR and run
mvn clean package -DskipTests
java -jar target/secureapp-1.0.0.jar
```

### Verify
```bash
curl http://localhost:8081/api/health
```

Expected response:
```json
{
  "success": true,
  "message": "Service is healthy",
  "data": { "status": "UP" },
  "statusCode": 200
}
```

---

## Default Test Credentials

| User      | Username   | Password        | Roles                    |
|-----------|------------|-----------------|--------------------------|
| Admin     | `admin`    | `AdminPass123!` | ROLE_ADMIN, ROLE_USER    |
| Test User | `testuser` | `UserPass123!`  | ROLE_USER                |

> ⚠️ **Change these passwords after first login in production!**

---

## Postman Collection

Import `SecureApp-API.postman_collection.json` for a complete API test suite including:
- Health check tests
- User registration (success + duplicate validation)
- Login with DPoP proof generation (pre-request scripts)
- JWT token-based protected endpoint access
- Role-based authorization tests (USER vs ADMIN)
- DPoP validation failure tests

The collection includes **pre-request scripts** that automatically generate ECDSA P-256 keypairs and DPoP proof JWTs for testing.

---

## Architecture Diagrams

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for detailed visual diagrams covering:
- High-level system overview (Client → Server → Database)
- Security filter chain pipeline (JWT + DPoP request processing)
- Login flow with DPoP key binding & JWT token generation
- Authenticated request flow (JWT + DPoP verification)
- Component dependency diagram
- DPoP attack prevention model
- Entity-relationship diagram
- Technology stack map
- Security headers response anatomy
