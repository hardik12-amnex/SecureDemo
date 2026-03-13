# SecureApp — Enterprise-Grade Spring Boot Security Backend

**Version:** 1.0.0  
**Java:** 21  
**Spring Boot:** 4.0.3  
**Last Updated:** March 12, 2026

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

SecureApp is a production-grade Spring Boot backend demonstrating enterprise security best practices. It implements **session-based authentication** with **DPoP (Demonstration of Proof-of-Possession)** binding, **JDBC-backed sessions**, **CSRF protection**, **role-based access control**, and comprehensive **security headers**.

DPoP ensures that even if a session cookie is stolen, the attacker cannot use it without possessing the client's private cryptographic key.

---

## Technology Stack

| Component             | Technology                          |
|-----------------------|-------------------------------------|
| Language              | Java 21                             |
| Framework             | Spring Boot 4.0.3                   |
| Security              | Spring Security 7.x                 |
| Session Store         | Spring Session JDBC (PostgreSQL)    |
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
│  3. Send request with DPoP header + session cookie                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      SPRING SECURITY FILTER CHAIN                    │
│                                                                      │
│  ┌──────────────────────────┐                                        │
│  │ DPoPAuthenticationFilter │ ← Validates DPoP proof JWT             │
│  │  • Parse & verify JWT     │   Checks JWK thumbprint vs session    │
│  │  • Replay protection (jti)│   Returns 401 if mismatch             │
│  └───────────┬──────────────┘                                        │
│              ▼                                                       │
│  ┌──────────────────────────┐                                        │
│  │ SessionValidationFilter  │ ← Validates session existence          │
│  │  • Session exists?        │   Checks expiry, authentication       │
│  │  • Session expired?       │   Returns 401 if invalid              │
│  │  • User authenticated?    │                                       │
│  └───────────┬──────────────┘                                        │
│              ▼                                                       │
│  ┌──────────────────────────┐                                        │
│  │ SecurityHeadersFilter    │ ← Adds CSP, HSTS, X-Frame-Options     │
│  └───────────┬──────────────┘                                        │
│              ▼                                                       │
│  ┌──────────────────────────┐                                        │
│  │ CSRF Filter (Spring)     │ ← CookieCsrfTokenRepository           │
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
│   ├── SecurityConfig.java                # Spring Security filter chain, CORS, CSRF, session mgmt
│   ├── SessionConfig.java                 # @EnableJdbcHttpSession (15-min timeout)
│   └── WebMvcConfig.java                  # Registers AuthorizationInterceptor
├── controller/
│   ├── AuthController.java                # Login (with DPoP binding), register, logout, /auth/me
│   └── DashboardController.java           # /health, /dashboard, /admin/users
├── dpop/
│   ├── DPoPAuthenticationFilter.java      # Filter: validates DPoP proof on every authenticated request
│   ├── DPoPConstants.java                 # Header names, claim keys, cache config constants
│   ├── DPoPProofValidator.java            # Parses & validates DPoP proof JWT (RFC 9449)
│   ├── DPoPReplayProtectionService.java   # Caffeine cache for jti replay protection
│   ├── DPoPSessionBindingService.java     # Binds client public key to session at login
│   └── DPoPValidationException.java       # Thrown when DPoP proof fails validation
├── dto/
│   ├── ApiResponse.java                   # Standard response wrapper {success, message, data, statusCode}
│   ├── LoginRequest.java                  # Login DTO {username, password}
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
│   ├── SecurityHeadersFilter.java         # Adds CSP, HSTS, X-Frame-Options, etc.
│   └── SessionValidationFilter.java       # Validates session + auth on protected endpoints
├── repository/
│   ├── RoleRepository.java                # JPA repository for Role
│   └── UserRepository.java               # JPA repository for User
├── security/
│   ├── AuthorizationInterceptor.java      # MVC interceptor: role-based path authorization
│   ├── CustomUserDetailsService.java      # Loads UserDetails from DB for Spring Security
│   └── RolePermissionMapping.java         # Centralized path → allowed-roles mapping
├── service/
│   └── AuthService.java                   # Business logic: register, login, getUserById
└── util/
    ├── SecurityUtil.java                  # Client IP detection, secure connection check
    └── SecurityUtils.java                 # Static: getCurrentUser(), getCurrentUserRoles(), hasRole()
```

---

## Security Features

### 1. Session-Based Authentication (JDBC-Backed)
- Sessions stored in PostgreSQL via Spring Session JDBC
- 15-minute session timeout (configurable)
- Session fixation protection: session ID rotated on login
- Maximum 1 concurrent session per user
- Secure cookie settings: `HttpOnly`, `Secure`, `SameSite=Strict`

### 2. DPoP (Demonstration of Proof-of-Possession) — RFC 9449
- Client generates an ECDSA P-256 keypair locally (browser WebCrypto API)
- At login, client sends a self-signed DPoP proof JWT with the public key embedded
- Server validates the proof and binds the public key to the session
- Every subsequent request must include a fresh DPoP proof signed by the same private key
- JWK thumbprint comparison prevents session cookie theft from being useful

### 3. CSRF Protection
- Enabled via `CookieCsrfTokenRepository` (cookie-based, `HttpOnly=false` for JS read)
- All state-changing requests (POST, PUT, DELETE, PATCH) require a valid CSRF token

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
Standard session cookies can be stolen via XSS, network interception, or browser extensions. DPoP adds a **cryptographic binding** — the client must prove it holds a private key that corresponds to the public key registered at login time.

### How It Works

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
5. Server validates credentials → validates DPoP proof → binds public key to session

SUBSEQUENT REQUESTS:
1. Client builds a fresh DPoP proof for the target endpoint
2. Client sends request with: Cookie: JSESSIONID=xxx + DPoP: <new-proof>
3. DPoPAuthenticationFilter:
   a. Parses & verifies the proof JWT signature
   b. Validates htm (HTTP method) and htu (request URI)
   c. Checks iat is within 5-minute window
   d. Checks jti uniqueness (replay protection via Caffeine cache)
   e. Compares JWK thumbprint with session-bound thumbprint
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
    "htu": "http://localhost:8080/api/dashboard",
    "iat": 1741785600,
    "jti": "unique-random-uuid"
  }
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
| JWK Thumbprint       | Must match the thumbprint bound to the session        |

---

## Request Flow

### Public Endpoints (No Authentication Required)
```
POST /api/auth/register   → Create new user account
POST /api/auth/login      → Authenticate + bind DPoP key to session
POST /api/auth/logout     → Invalidate session
GET  /api/health          → Health check
```

### Protected Endpoints (Session + DPoP Required)
```
Request → DPoPAuthenticationFilter → SessionValidationFilter
        → AuthorizationInterceptor → Controller

GET  /api/auth/me          → Get current authenticated user
GET  /api/dashboard        → Dashboard (ROLE_USER, ROLE_ADMIN)
GET  /api/admin/users      → Admin-only user list (ROLE_ADMIN)
```

---

## API Reference

### Base URL
```
http://localhost:8080/api
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
  "timestamp": "2026-03-12T10:00:00Z"
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
    "createdAt": "2026-03-12T10:00:00",
    "updatedAt": "2026-03-12T10:00:00"
  },
  "statusCode": 201
}
```

#### POST /auth/login
Authenticate the user, rotate session, and bind DPoP public key.

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
    "id": 2,
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "roles": ["ROLE_USER"],
    "lastLogin": "2026-03-12T10:00:00"
  },
  "statusCode": 200
}
```

**Response Headers (set by server):**
- `Set-Cookie: JSESSIONID=<new-session-id>; Path=/; HttpOnly; Secure; SameSite=Strict`

#### POST /auth/logout
Invalidate the current session.

**Response (200):**
```json
{
  "success": true,
  "message": "Logout successful",
  "data": null,
  "statusCode": 200
}
```

#### GET /auth/me (Protected)
Get the currently authenticated user's profile.

**Required Headers:**
- `DPoP: <fresh-dpop-proof-jwt>`
- `Cookie: JSESSIONID=<session-id>`

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
2. **DPoPAuthenticationFilter** — Validates cryptographic proof-of-possession
3. **SessionValidationFilter** — Validates session existence and attributes
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
| `SPRING_SESSION`            | JDBC-backed HTTP sessions                        |
| `SPRING_SESSION_ATTRIBUTES` | Session attribute storage (incl. DPoP keys)      |

---

## Configuration

### Key Properties (`application.properties`)

| Property                                    | Value                   | Description                              |
|---------------------------------------------|-------------------------|------------------------------------------|
| `server.port`                               | `8080`                  | Application port                         |
| `server.servlet.context-path`               | `/api`                  | All URLs prefixed with `/api`            |
| `spring.session.store-type`                 | `jdbc`                  | Sessions stored in PostgreSQL            |
| `server.servlet.session.timeout`            | `15m`                   | Session timeout                          |
| `server.servlet.session.cookie.http-only`   | `true`                  | Cookie not accessible via JavaScript     |
| `server.servlet.session.cookie.secure`      | `true`                  | Cookie sent only over HTTPS              |
| `server.servlet.session.cookie.same-site`   | `strict`                | CSRF mitigation                          |
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
curl http://localhost:8080/api/health
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
- Session-based protected endpoint access
- Role-based authorization tests (USER vs ADMIN)
- Session invalidation / post-logout verification
- DPoP validation failure tests

The collection includes **pre-request scripts** that automatically generate ECDSA P-256 keypairs and DPoP proof JWTs for testing.

---

## Architecture Diagrams

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for detailed visual diagrams covering:
- High-level system overview (Client → Server → Database)
- Security filter chain pipeline (9-step request processing)
- Login flow with DPoP key binding & session creation
- Authenticated request flow (DPoP + session verification)
- Component dependency diagram
- Session lifecycle & storage
- DPoP attack prevention model (5 attack scenarios)
- Entity-relationship diagram
- Technology stack map
- Security headers response anatomy