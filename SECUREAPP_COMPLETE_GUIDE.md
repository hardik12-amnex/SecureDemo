# SecureApp - Complete Project Guide

> **One document to understand the entire project** - architecture, security, code, testing, and deployment.
> Cross-references every existing documentation file so you always know where to go for more detail.

---

## Table of Contents

1. [What Is SecureApp](#1-what-is-secureapp)
2. [Technology Stack](#2-technology-stack)
3. [Project Structure and Source Files](#3-project-structure-and-source-files)
4. [Application Architecture](#4-application-architecture)
5. [Security Architecture (Defense in Depth)](#5-security-architecture-defense-in-depth)
6. [How Every Security Feature Works](#6-how-every-security-feature-works)
7. [Request Lifecycle (Step by Step)](#7-request-lifecycle-step-by-step)
8. [API Endpoints](#8-api-endpoints)
9. [Database Design](#9-database-design)
10. [Configuration Reference](#10-configuration-reference)
11. [How to Build and Run](#11-how-to-build-and-run)
12. [How to Test the Whole Project](#12-how-to-test-the-whole-project)
13. [Production Deployment](#13-production-deployment)
14. [Documentation Index (All Files Explained)](#14-documentation-index-all-files-explained)

---

## 1. What Is SecureApp

**SecureApp** is a production-grade Spring Boot 4.0.3 backend that demonstrates enterprise-level security. It was built for the **Agristack** initiative as a reference implementation showing how to build a secure REST API from scratch.

### What It Does

- Lets users **register** and **login** with username/password
- Creates **server-side sessions** stored in PostgreSQL (not JWT)
- Enforces **role-based access control** (User vs Admin endpoints)
- Applies **8 security headers** to every HTTP response
- Protects against **CSRF**, **XSS**, **clickjacking**, **MIME-sniffing**, and **session hijacking**
- Validates **all user input** with Jakarta Bean Validation
- Provides a **Postman collection** for immediate API testing

### Why Session-Based (Not JWT)

| Feature | Sessions (our choice) | JWT |
|---------|:--------------------:|:---:|
| Instant invalidation (logout) | Yes - delete from DB | No - valid until expiry |
| Sensitive data exposure to client | No - only random ID | Yes - payload visible |
| Server-side control | Full (timeout, max sessions) | Limited |
| Built-in Spring Security support | Native | Requires custom filters |

> **Read more**: [README.md](./README.md) for project overview, [PROJECT_SUMMARY.txt](./PROJECT_SUMMARY.txt) for completion report

---

## 2. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Language | Java | 21 | Core language |
| Framework | Spring Boot | 4.0.3 | Application framework |
| Security | Spring Security | Latest | Auth, CSRF, CORS, headers |
| Database | PostgreSQL | 42.7.3 driver | Data + session storage |
| Session Store | Spring Session JDBC | Latest | DB-backed sessions |
| ORM | Spring Data JPA / Hibernate | Latest | Object-relational mapping |
| Validation | Jakarta Bean Validation | Latest | Input validation |
| Build | Maven | 3.9.12+ | Build and dependency management |
| Utilities | Lombok | Latest | Boilerplate reduction |
| Monitoring | Spring Actuator | Latest | Health checks |
| Serialization | Jackson | Latest | JSON processing |

### Key Maven Dependencies (from `pom.xml`)

```
spring-boot-starter-web          → REST controllers
spring-boot-starter-security     → Spring Security
spring-boot-starter-data-jpa     → JPA/Hibernate
spring-session-jdbc              → JDBC session store
spring-boot-starter-validation   → Jakarta Validation
spring-boot-starter-actuator     → Health endpoints
postgresql                       → PostgreSQL driver
lombok                           → Annotations
jackson-databind                 → JSON serialization
jakarta.servlet-api              → Servlet API
spring-boot-starter-test         → Testing
spring-security-test             → Security testing
```

---

## 3. Project Structure and Source Files

```
E:\Projects\Agristack\poc\SecureDemo\
│
├── pom.xml                              # Maven build (114 lines)
├── init-database.sql                    # Schema + seed data + session tables (204 lines)
├── SecureApp-API.postman_collection.json # Postman collection (863 lines)
│
├── src/main/java/com/example/secureapp/
│   │
│   ├── SecureAppApplication.java        # @SpringBootApplication entry point (13 lines)
│   │
│   ├── config/                          # === CONFIGURATION ===
│   │   ├── SecurityConfig.java          # ★ Main security: CORS, CSRF, sessions, auth rules (146 lines)
│   │   ├── SessionConfig.java           # @EnableJdbcHttpSession, 900s timeout (18 lines)
│   │   └── WebMvcConfig.java            # Registers AuthorizationInterceptor (46 lines)
│   │
│   ├── controller/                      # === REST ENDPOINTS ===
│   │   ├── AuthController.java          # /auth/register, /auth/login, /auth/logout, /auth/me (82 lines)
│   │   └── DashboardController.java     # /health, /dashboard, /admin/users (67 lines)
│   │
│   ├── service/                         # === BUSINESS LOGIC ===
│   │   └── AuthService.java             # register(), login(), getUserById() (127 lines)
│   │
│   ├── repository/                      # === DATA ACCESS ===
│   │   ├── UserRepository.java          # findByUsername, existsByUsername, existsByEmail (26 lines)
│   │   └── RoleRepository.java          # findByName (14 lines)
│   │
│   ├── entity/                          # === JPA ENTITIES ===
│   │   ├── User.java                    # users table: id, username, email, password, roles... (97 lines)
│   │   └── Role.java                    # roles table: id, name, description (51 lines)
│   │
│   ├── dto/                             # === DATA TRANSFER OBJECTS ===
│   │   ├── LoginRequest.java            # @NotBlank username, @Size password (23 lines)
│   │   ├── SignUpRequest.java           # username, email, firstName, lastName, password... (40 lines)
│   │   ├── UserResponse.java            # id, username, email, roles, timestamps (30 lines)
│   │   └── ApiResponse.java             # Generic wrapper: success, message, data, statusCode (39 lines)
│   │
│   ├── security/                        # === SECURITY COMPONENTS ===
│   │   ├── CustomUserDetailsService.java # Loads User from DB for Spring Security auth (44 lines)
│   │   ├── AuthorizationInterceptor.java # MVC interceptor: role-based path auth + logging (123 lines)
│   │   └── RolePermissionMapping.java   # Centralized path→roles map with AntPathMatcher (88 lines)
│   │
│   ├── filter/                          # === HTTP FILTERS ===
│   │   ├── SecurityHeadersFilter.java   # Adds 8 security headers to every response (80 lines)
│   │   └── SessionValidationFilter.java # 4-step session validation, 401 on failure (150 lines)
│   │
│   ├── exception/                       # === ERROR HANDLING ===
│   │   ├── BadRequestException.java     # 400 errors (15 lines)
│   │   ├── ResourceNotFoundException.java # 404 errors (15 lines)
│   │   └── GlobalExceptionHandler.java  # @RestControllerAdvice — catches all exceptions (46 lines)
│   │
│   └── util/                            # === UTILITIES ===
│       ├── SecurityUtil.java            # getClientIp(), isSecureConnection() (27 lines)
│       └── SecurityUtils.java           # Static: getCurrentUser(), hasRole(), isAuthenticated() (122 lines)
│
├── src/main/resources/
│   └── application.properties           # All configuration (61 lines)
│
└── Documentation (10 files)             # See Section 14
```

### Total: 24 Java source files across 10 packages

---

## 4. Application Architecture

### High-Level Flow

```
                          ┌─────────────────────────┐
                          │   Angular Frontend      │
                          │   http://localhost:4200  │
                          └───────────┬─────────────┘
                                      │ HTTP (JSON)
                          ┌───────────▼─────────────┐
                          │   Spring Boot Backend   │
                          │   http://localhost:8080  │
                          │   Context: /api          │
                          ├─────────────────────────┤
                          │  Security Filter Chain   │
                          │  (CORS → Headers → CSRF  │
                          │   → Session → Auth)      │
                          ├─────────────────────────┤
                          │  AuthorizationInterceptor│
                          │  (RolePermissionMapping)  │
                          ├─────────────────────────┤
                          │  Controllers             │
                          │  AuthController           │
                          │  DashboardController      │
                          ├─────────────────────────┤
                          │  Services                 │
                          │  AuthService              │
                          ├─────────────────────────┤
                          │  Repositories (JPA)       │
                          │  UserRepository           │
                          │  RoleRepository           │
                          └───────────┬─────────────┘
                                      │ JDBC
                          ┌───────────▼─────────────┐
                          │      PostgreSQL         │
                          │   secureapp_db           │
                          │                         │
                          │  Tables:                │
                          │  - users                │
                          │  - roles                │
                          │  - user_roles           │
                          │  - SPRING_SESSION       │
                          │  - SPRING_SESSION_ATTRS  │
                          └─────────────────────────┘
```

### Registration → Login → Use → Logout

```
1. REGISTER  POST /api/auth/register
   Client sends: { username, email, password, confirmPassword, firstName, lastName }
   Server does:  Validate → Check uniqueness → BCrypt hash → Save with ROLE_USER → Return UserResponse
   Result:       201 Created

2. LOGIN     POST /api/auth/login
   Client sends: { username, password }
   Server does:  Load user → BCrypt verify → Create session → Store userId/username/roles in session
   Result:       200 OK + Set-Cookie: JSESSIONID=xxx (HttpOnly, Secure, SameSite=Strict)

3. USE       GET /api/dashboard  (Cookie: JSESSIONID=xxx)
   Server does:  SessionValidationFilter validates session
                 → AuthorizationInterceptor checks role permissions
                 → @PreAuthorize("isAuthenticated()") on method
                 → Controller reads username from session → Returns dashboard data
   Result:       200 OK

4. LOGOUT    POST /api/auth/logout  (Cookie: JSESSIONID=xxx)
   Server does:  Invalidate session in DB → Delete JSESSIONID cookie → Clear auth context
   Result:       200 OK + Set-Cookie: JSESSIONID=; Max-Age=0
```

> **Read more**: [SECURITY_IMPLEMENTATION.md](./SECURITY_IMPLEMENTATION.md) → "Authentication Flow"

---

## 5. Security Architecture (Defense in Depth)

The project implements **11 layers of security**. If one layer is bypassed, others still protect the system. Each layer maps to specific source files:

```
 Layer    What It Does                              Source File
 ─────    ──────────────────────────────────────    ──────────────────────────────
  1       CORS Policy (only localhost:4200)          SecurityConfig.java
  2       HTTPS + HSTS enforcement                  SecurityHeadersFilter.java
  3       Cookie flags (HttpOnly/Secure/SameSite)   application.properties
  4       CSRF token validation                     SecurityConfig.java
  5       Security headers (8 headers)              SecurityConfig.java + SecurityHeadersFilter.java
  6       Session validation (exists + not expired)  SessionValidationFilter.java
  7       Authentication (username/password)         CustomUserDetailsService.java + AuthService.java
  8       URL-level authorization                   SecurityConfig.java (authorizeHttpRequests)
  9       Interceptor authorization (role→path)     AuthorizationInterceptor.java + RolePermissionMapping.java
 10       Method-level authorization                @PreAuthorize on controller methods
 11       Input validation                          Jakarta Validation on DTOs + GlobalExceptionHandler.java
```

### The Two Authorization Systems (Important!)

This project has **two complementary authorization mechanisms** that work together:

**1. Spring Security Authorization (Layer 8)** — in `SecurityConfig.java`:
```java
.authorizeHttpRequests(authz -> authz
    .requestMatchers("/auth/login", "/auth/register", "/auth/logout").permitAll()
    .requestMatchers("/api/health", "/actuator/health", "/health").permitAll()
    .anyRequest().authenticated()   // ← Everything else needs a valid session
)
```

**2. Custom AuthorizationInterceptor (Layer 9)** — in `AuthorizationInterceptor.java` + `RolePermissionMapping.java`:
```
Path Pattern          → Allowed Roles
/admin/**             → ROLE_ADMIN
/activity/admin/**    → ROLE_ADMIN
/activity/profile/**  → ROLE_USER, ROLE_ADMIN
/activity/action/**   → ROLE_USER, ROLE_ADMIN
/dashboard/**         → ROLE_USER, ROLE_ADMIN
(no mapping)          → Defer to Spring Security (allow if authenticated)
```

**And** controller methods can add a third check with `@PreAuthorize`:
```java
@PreAuthorize("hasRole('ADMIN')")   // Only ROLE_ADMIN
@PreAuthorize("isAuthenticated()")  // Any logged-in user
```

All three work together. A request must pass ALL of them.

> **Read more**: [SECURITY_CONFIGURATION_MATRIX.md](./SECURITY_CONFIGURATION_MATRIX.md) → filter chain order + configuration matrix
>
> **Read more**: [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) → architecture diagram + security checklist

---

## 6. How Every Security Feature Works

### 6.1 Session-Based Authentication

| Aspect | Detail |
|--------|--------|
| **Store** | PostgreSQL via JDBC (`SPRING_SESSION` + `SPRING_SESSION_ATTRIBUTES` tables) |
| **Timeout** | 15 minutes (900 seconds) — configurable in `application.properties` |
| **Max sessions** | 1 per user — new login replaces old session |
| **Cookie name** | `JSESSIONID` |
| **Creation policy** | `IF_REQUIRED` — session created only when needed |
| **Config files** | `SecurityConfig.java`, `SessionConfig.java`, `application.properties` |

The `SessionValidationFilter` adds defense-in-depth with 4 checks:
1. Session exists (`request.getSession(false) != null`)
2. Session not expired (explicit time check)
3. Authenticated user in `SecurityContextHolder`
4. `username` attribute present in session

### 6.2 Cookie Security Flags

Set in `application.properties`:

| Flag | Value | What It Prevents |
|------|-------|-----------------|
| `HttpOnly` | `true` | JavaScript cannot read the cookie → prevents XSS cookie theft |
| `Secure` | `true` | Cookie only sent over HTTPS → prevents network sniffing |
| `SameSite` | `Strict` | Cookie not sent in cross-site requests → prevents CSRF |
| `Max-Age` | `900` | Cookie auto-expires after 15 minutes |

### 6.3 CSRF Protection

- **Method**: Double-submit cookie pattern via `CookieCsrfTokenRepository.withHttpOnlyFalse()`
- **How it works**: Server sets `XSRF-TOKEN` cookie → client reads it → client sends it back as `X-XSRF-TOKEN` header → server compares both
- **Applied to**: POST, PUT, DELETE, PATCH (state-changing requests)
- **Not applied to**: GET, HEAD, OPTIONS (read-only requests)

### 6.4 Security Headers (8 Headers)

Set by `SecurityConfig.java` (CSP, X-Frame-Options) and `SecurityHeadersFilter.java` (all others):

| # | Header | Value | Attack Prevented |
|---|--------|-------|-----------------|
| 1 | `Content-Security-Policy` | `default-src 'self'; script-src 'self'; ...` | XSS |
| 2 | `X-Frame-Options` | `DENY` | Clickjacking |
| 3 | `X-Content-Type-Options` | `nosniff` | MIME confusion |
| 4 | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Downgrade attacks |
| 5 | `X-XSS-Protection` | `1; mode=block` | Reflected XSS (legacy) |
| 6 | `Referrer-Policy` | `strict-origin-when-cross-origin` | URL leakage |
| 7 | `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), ...` | Feature abuse |
| 8 | `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` | Sensitive data caching |

### 6.5 CORS (Cross-Origin Resource Sharing)

Configured in `SecurityConfig.java → corsConfigurationSource()`:

| Setting | Value |
|---------|-------|
| Allowed origin | `http://localhost:4200` |
| Allowed methods | GET, POST, PUT, DELETE, OPTIONS, PATCH |
| Allowed headers | `*` (all) |
| Exposed headers | Authorization, Content-Type |
| Credentials | `true` (cookies allowed) |
| Preflight cache | 3600 seconds (1 hour) |

### 6.6 Password Hashing

- **Algorithm**: BCrypt with strength 12 (2^12 = 4,096 rounds)
- **Salt**: Automatically generated per password
- **Config**: `SecurityConfig.java → BCryptPasswordEncoder(12)`
- **Storage**: Hashes start with `$2a$12$` in the database

### 6.7 Role-Based Access Control (RBAC)

**Roles seeded by `init-database.sql`:**

| Role | Description | Access |
|------|-------------|--------|
| `ROLE_USER` | Standard user | `/dashboard`, `/auth/me`, own profile |
| `ROLE_ADMIN` | Administrator | Everything including `/admin/**` |
| `ROLE_MODERATOR` | Content moderator | Content management endpoints |

**Pre-seeded test users:**

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `AdminPass123!` | ROLE_ADMIN + ROLE_USER |
| `testuser` | `UserPass123!` | ROLE_USER |

### 6.8 Input Validation

DTOs use Jakarta Validation annotations. `GlobalExceptionHandler` catches `MethodArgumentNotValidException` and returns clean JSON:

| DTO | Validations |
|-----|------------|
| `LoginRequest` | `@NotBlank` username, `@NotBlank @Size(min=6)` password |
| `SignUpRequest` | `@NotBlank @Size(3-50)` username, `@Email` email, `@Size(8-128)` password, `@NotBlank` confirmPassword |

### 6.9 Method-Level Security

Three annotation styles enabled via `@EnableMethodSecurity(prePostEnabled=true, securedEnabled=true, jsr250Enabled=true)`:

```java
@PreAuthorize("hasRole('ADMIN')")         // SpEL expression
@PreAuthorize("isAuthenticated()")        // Any logged-in user
@Secured("ROLE_USER")                     // Role check
@RolesAllowed("ROLE_MODERATOR")           // JSR-250 standard
```

Used in the project:
- `DashboardController.dashboard()` → `@PreAuthorize("isAuthenticated()")`
- `DashboardController.getUsers()` → `@PreAuthorize("hasRole('ADMIN')")`

> **Read more**: [SECURITY_IMPLEMENTATION.md](./SECURITY_IMPLEMENTATION.md) → comprehensive deep-dive on each feature
>
> **Read more**: [DEVELOPER_QUICK_REFERENCE.md](./DEVELOPER_QUICK_REFERENCE.md) → code examples for adding new secured endpoints

---

## 7. Request Lifecycle (Step by Step)

When a browser sends `GET /api/dashboard` with a `JSESSIONID` cookie, here is the **exact sequence**:

```
Step 1: CorsFilter
        └─ Is Origin http://localhost:4200? → YES → Add CORS headers, continue

Step 2: SecurityHeadersFilter (custom, 80 lines)
        └─ Add all 8 security headers to response → continue

Step 3: CsrfFilter
        └─ Is this a GET request? → YES → Skip CSRF check → continue
           (POST/PUT/DELETE would require X-XSRF-TOKEN header)

Step 4: SessionValidationFilter (custom, 150 lines)
        ├─ Is path public (/auth/login, /auth/register, /health)? → NO
        ├─ Does session exist? → YES (found in SPRING_SESSION table)
        ├─ Is session expired? → NO (within 900 seconds)
        ├─ Is user authenticated in SecurityContext? → YES
        ├─ Is username in session? → YES
        └─ All 4 checks passed → continue

Step 5: Spring Security AuthorizationFilter
        ├─ Is path in permitAll()? → NO
        ├─ Is user authenticated? → YES
        └─ .anyRequest().authenticated() → PASS → continue

Step 6: AuthorizationInterceptor (custom, 123 lines)
        ├─ Get path: /dashboard
        ├─ Get user roles: [ROLE_USER]
        ├─ Get allowed roles from RolePermissionMapping: [ROLE_USER, ROLE_ADMIN]
        ├─ Does user have any allowed role? → YES (ROLE_USER matches)
        ├─ Log: "Authorization | User: testuser | Role: [ROLE_USER] | Endpoint: /dashboard | Result: ALLOWED"
        └─ return true → continue

Step 7: DashboardController.dashboard()
        ├─ @PreAuthorize("isAuthenticated()") → PASS
        ├─ Read username from session → "testuser"
        ├─ Build response: { message: "Welcome to dashboard, testuser" }
        └─ Return ApiResponse with 200 OK

Step 8: Response sent to client
        ├─ JSON body: { success: true, message: "Dashboard data fetched", data: {...} }
        ├─ All 8 security headers attached
        └─ JSESSIONID cookie maintained
```

**If any step fails:**
- Step 4 fails → `401 Unauthorized` (JSON: `{ status: "ERROR", message: "Session invalid or expired" }`)
- Step 5 fails → `401 Unauthorized`
- Step 6 fails → `403 Forbidden` (JSON: `{ status: "ERROR", message: "Access denied" }`)
- Step 7 `@PreAuthorize` fails → `403 Forbidden`

> **Read more**: [SECURITY_CONFIGURATION_MATRIX.md](./SECURITY_CONFIGURATION_MATRIX.md) → filter chain order diagram + troubleshooting decision tree

---

## 8. API Endpoints

Base URL: `http://localhost:8080/api`

### Public Endpoints (No Authentication)

| Method | URL | Purpose | Status Code |
|--------|-----|---------|:-----------:|
| `GET` | `/api/health` | Health check | 200 |
| `POST` | `/api/auth/register` | Register new user | 201 |
| `POST` | `/api/auth/login` | Login (creates session) | 200 |
| `POST` | `/api/auth/logout` | Logout (destroys session) | 200 |

### Protected Endpoints (Session Required)

| Method | URL | Required Role | Purpose | Status Code |
|--------|-----|:------------:|---------|:-----------:|
| `GET` | `/api/auth/me` | Any authenticated | Get current user | 200 |
| `GET` | `/api/dashboard` | ROLE_USER or ROLE_ADMIN | User dashboard | 200 |
| `GET` | `/api/admin/users` | ROLE_ADMIN only | Admin user list | 200 |

### Standard Response Format

**Success:**
```json
{
  "success": true,
  "message": "Dashboard data fetched",
  "statusCode": 200,
  "data": { "message": "Welcome to dashboard, testuser", "timestamp": 1741689600000 },
  "timestamp": 1741689600000
}
```

**Error:**
```json
{
  "success": false,
  "message": "Username already taken",
  "statusCode": 400,
  "timestamp": 1741689600000
}
```

> **Read more**: [README.md](./README.md) → full request/response examples for each endpoint
>
> **Postman collection**: Import [SecureApp-API.postman_collection.json](./SecureApp-API.postman_collection.json)

---

## 9. Database Design

### Tables (created by `init-database.sql`)

```
┌──────────────────┐     ┌──────────────┐     ┌──────────────────┐
│      roles       │     │  user_roles  │     │      users       │
├──────────────────┤     ├──────────────┤     ├──────────────────┤
│ id (PK, BIGSERIAL)│◄───│ role_id (FK) │     │ id (PK, BIGSERIAL)│
│ name (UNIQUE)    │     │ user_id (FK) │────►│ username (UNIQUE)│
│ description      │     └──────────────┘     │ email (UNIQUE)   │
│ created_at       │                          │ password (BCrypt) │
│ updated_at       │                          │ first_name       │
└──────────────────┘                          │ last_name        │
                                              │ phone_number     │
                                              │ address          │
                                              │ enabled          │
                                              │ account_non_*    │
                                              │ created_at       │
                                              │ updated_at       │
                                              │ last_login       │
                                              └──────────────────┘

┌─────────────────────────────────┐     ┌───────────────────────────────────┐
│        SPRING_SESSION           │     │    SPRING_SESSION_ATTRIBUTES      │
├─────────────────────────────────┤     ├───────────────────────────────────┤
│ PRIMARY_ID (PK, CHAR(36))       │◄────│ SESSION_PRIMARY_ID (FK, CHAR(36)) │
│ SESSION_ID (UNIQUE, CHAR(36))   │     │ ATTRIBUTE_NAME (VARCHAR(200))     │
│ CREATION_TIME (BIGINT)          │     │ ATTRIBUTE_BYTES (BYTEA)           │
│ LAST_ACCESSED_TIME (BIGINT)     │     └───────────────────────────────────┘
│ MAX_INACTIVE_INTERVAL (INT)     │
│ EXPIRY_TIME (BIGINT)            │
│ PRINCIPAL_NAME (VARCHAR(100))   │
└─────────────────────────────────┘
```

### Seeded Data

**Roles:** `ROLE_USER`, `ROLE_ADMIN`, `ROLE_MODERATOR`

**Test Users:**

| Username | Password | Email | Roles |
|----------|----------|-------|-------|
| `admin` | `AdminPass123!` | admin@secureapp.com | ROLE_ADMIN, ROLE_USER |
| `testuser` | `UserPass123!` | test@example.com | ROLE_USER |

### Indexes

- `idx_username` on `users(username)`
- `idx_email` on `users(email)`
- `idx_enabled` on `users(enabled)`
- `idx_role_name` on `roles(name)`
- Spring Session indexes on `SESSION_ID`, `EXPIRY_TIME`, `PRINCIPAL_NAME`

---

## 10. Configuration Reference

All configuration is in `src/main/resources/application.properties` (61 lines):

### Server
| Property | Value | Purpose |
|----------|-------|---------|
| `server.port` | `8080` | HTTP port |
| `server.servlet.context-path` | `/api` | All URLs start with /api |

### Session & Cookies
| Property | Value | Purpose |
|----------|-------|---------|
| `spring.session.store-type` | `jdbc` | Sessions stored in PostgreSQL |
| `spring.session.jdbc.initialize-schema` | `never` | Tables created by init-database.sql |
| `server.servlet.session.timeout` | `15m` | Session expires after 15 min inactivity |
| `server.servlet.session.cookie.name` | `JSESSIONID` | Cookie name |
| `server.servlet.session.cookie.http-only` | `true` | JS cannot read cookie |
| `server.servlet.session.cookie.secure` | `true` | HTTPS only |
| `server.servlet.session.cookie.same-site` | `strict` | No cross-site sending |
| `server.servlet.session.cookie.max-age` | `900` | 15 min cookie lifetime |

### Database
| Property | Value |
|----------|-------|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/secureapp_db` |
| `spring.datasource.username` | `postgres` |
| `spring.datasource.password` | `postgres` |
| `spring.jpa.hibernate.ddl-auto` | `update` |
| `spring.datasource.hikari.maximum-pool-size` | `10` |

### Security
| Property | Value |
|----------|-------|
| `app.security.enable-csrf` | `true` |
| `app.security.cors.allowed-origins` | `http://localhost:4200` |
| `app.security.cors.allow-credentials` | `true` |

### Logging
| Property | Value |
|----------|-------|
| `logging.level.com.example.secureapp` | `DEBUG` |
| `logging.level.org.springframework.security` | `DEBUG` |
| `logging.file.name` | `logs/secureapp.log` |

> **Read more**: [SECURITY_CONFIGURATION_MATRIX.md](./SECURITY_CONFIGURATION_MATRIX.md) → complete configuration matrix with every setting

---

## 11. How to Build and Run

### Prerequisites

| Tool | Version | Verify |
|------|---------|--------|
| Java JDK | 21+ | `java -version` |
| Maven | 3.9.12+ | `mvn --version` |
| PostgreSQL | 12+ | `psql --version` |

### Step-by-Step

```bash
# 1. Create the database
psql -U postgres -h localhost -c "CREATE DATABASE secureapp_db;"

# 2. Run the init script (creates tables + seed data + Spring Session tables)
psql -U postgres -h localhost -d secureapp_db -f init-database.sql

# 3. Update database password in application.properties if needed

# 4. Build
cd E:\Projects\Agristack\poc\SecureDemo
mvn clean package -DskipTests

# 5. Run
java -jar target/secureapp-1.0.0.jar
# OR
mvn spring-boot:run

# 6. Verify
curl http://localhost:8080/api/health
# Expected: { "success": true, "data": { "status": "UP" } }
```

> **Tip**: For local HTTP testing, set `server.servlet.session.cookie.secure=false` in `application.properties` since the `Secure` flag requires HTTPS.

> **Read more**: [README.md](./README.md) → "Setup & Installation" section

---

## 12. How to Test the Whole Project

### Quick Smoke Test (5 commands)

```bash
:: 1. Health check (public)
curl http://localhost:8080/api/health

:: 2. Register
curl -X POST http://localhost:8080/api/auth/register -H "Content-Type: application/json" -d "{\"username\":\"myuser\",\"email\":\"my@test.com\",\"firstName\":\"My\",\"lastName\":\"User\",\"password\":\"SecurePass123!\",\"confirmPassword\":\"SecurePass123!\"}"

:: 3. Login (saves session cookie)
curl -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" -c cookies.txt -d "{\"username\":\"myuser\",\"password\":\"SecurePass123!\"}"

:: 4. Access protected endpoint (uses session cookie)
curl http://localhost:8080/api/dashboard -b cookies.txt

:: 5. Access admin endpoint as regular user (should get 403)
curl http://localhost:8080/api/admin/users -b cookies.txt
```

### What to Test and Expected Results

| Test | Command | Expected |
|------|---------|----------|
| Public health | `curl /api/health` | 200 OK |
| Register user | `POST /api/auth/register` | 201 Created |
| Duplicate user | `POST /api/auth/register` (same data) | 400 Bad Request |
| Login | `POST /api/auth/login` | 200 + JSESSIONID cookie |
| Dashboard with session | `GET /api/dashboard -b cookies.txt` | 200 OK |
| Dashboard without session | `GET /api/dashboard` | 401 Unauthorized |
| Admin as USER | `GET /api/admin/users -b cookies.txt` (ROLE_USER) | 403 Forbidden |
| Admin as ADMIN | `GET /api/admin/users -b admin_cookies.txt` | 200 OK |
| Security headers | `curl -v /api/health` | All 8 headers in response |
| Cookie flags | Check `Set-Cookie` after login | HttpOnly; Secure; SameSite=Strict |
| Session expiry | Wait 15 min, then `GET /api/dashboard` | 401 Unauthorized |
| After logout | `POST /api/auth/logout`, then `GET /api/dashboard` | 401 Unauthorized |
| Empty fields | `POST /api/auth/register {}` | 400 + validation errors |
| SQL injection | Login with `' OR 1=1 --` | 401 (JPA uses parameterized queries) |
| Fake session ID | `Cookie: JSESSIONID=fake123` | 401 Unauthorized |
| Wrong CORS origin | `Origin: http://evil.com` | No Access-Control-Allow-Origin |

### Testing Tools

| Tool | Purpose |
|------|---------|
| **cURL** | Command-line API testing |
| **Postman** | Import `SecureApp-API.postman_collection.json` — visual API testing with auto cookie management |
| **Browser DevTools** | Network tab for headers, Application tab for cookies |
| **MockMvc** | Automated unit/integration tests in Java |

> **Read more**: [TESTING_AND_SECURITY_CONCEPTS_GUIDE.md](./TESTING_AND_SECURITY_CONCEPTS_GUIDE.md) → comprehensive testing guide with step-by-step commands, security concept explanations, negative tests, and automated test code examples

---

## 13. Production Deployment

### Checklist

- [ ] Enable HTTPS (`server.ssl.enabled=true`, configure keystore)
- [ ] Update CORS origin to production domain
- [ ] Set database credentials via environment variables
- [ ] Keep `server.servlet.session.cookie.secure=true`
- [ ] Adjust session timeout as needed
- [ ] Set logging to WARN/INFO level for Spring Security
- [ ] Register for HSTS preload at https://hstspreload.org/
- [ ] Set up database backups
- [ ] Monitor active sessions, failed logins, CSRF failures
- [ ] Run `init-database.sql` on production database

### Docker

```dockerfile
FROM openjdk:21-jdk-slim
COPY target/secureapp-1.0.0.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

```bash
docker build -t secureapp:1.0.0 .
docker run -p 8080:8080 --env-file .env secureapp:1.0.0
```

### Environment Variables (Production)

```
SPRING_DATASOURCE_URL=jdbc:postgresql://prod-host:5432/secureapp_db
SPRING_DATASOURCE_USERNAME=prod_user
SPRING_DATASOURCE_PASSWORD=strong_password
SERVER_PORT=8443
```

> **Read more**: [IMPLEMENTATION_VALIDATION.md](./IMPLEMENTATION_VALIDATION.md) → deployment checklist + monitoring + alerts setup

---

## 14. Documentation Index (All Files Explained)

This project has **10 documentation files**. Here is exactly what each one covers, who should read it, and how long it takes:

| # | File | Contents | Audience | Time |
|---|------|----------|----------|------|
| 1 | [README.md](./README.md) | Project overview, tech stack, API docs with request/response examples, setup instructions, cURL testing, deployment | Everyone - start here | 15 min |
| 2 | [SECURITY_DOCUMENTATION_INDEX.md](./SECURITY_DOCUMENTATION_INDEX.md) | Master index of all docs, implementation file details, security requirements status, quick-start by role | Navigation hub | 5 min |
| 3 | [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md) | Checklist of all completed tasks, files created/modified, architecture diagram, config reference | Project managers | 5 min |
| 4 | [SECURITY_IMPLEMENTATION.md](./SECURITY_IMPLEMENTATION.md) | Deep-dive: session config, CSRF, CORS, headers, auth flow, password encoding, dev vs prod, testing, troubleshooting | Security engineers | 20 min |
| 5 | [DEVELOPER_QUICK_REFERENCE.md](./DEVELOPER_QUICK_REFERENCE.md) | Code examples: @PreAuthorize, @Secured, CSRF in Angular, cURL/Postman, all security files overview | Backend developers | 10 min |
| 6 | [SECURITY_CONFIGURATION_MATRIX.md](./SECURITY_CONFIGURATION_MATRIX.md) | Configuration lookup tables, header details, filter chain order, RBAC map, endpoint security map, troubleshooting decision tree | DevOps, sysadmins | 10 min |
| 7 | [IMPLEMENTATION_VALIDATION.md](./IMPLEMENTATION_VALIDATION.md) | Requirement-by-requirement validation, all file changes, compilation status, test recommendations, deployment checklist, monitoring | QA, release mgrs | 15 min |
| 8 | [SPRING_SECURITY_GUIDE.md](./SPRING_SECURITY_GUIDE.md) | Complete implementation guide: all files with sizes, doc navigation, config quick reference, environment configs, learning resources | New team members | 15 min |
| 9 | [TESTING_AND_SECURITY_CONCEPTS_GUIDE.md](./TESTING_AND_SECURITY_CONCEPTS_GUIDE.md) | Step-by-step testing (cURL, Postman, Browser), security concept "why" explanations, negative/pen tests, automated test code | QA testers, learners | 20 min |
| 10 | **SECUREAPP_COMPLETE_GUIDE.md** (this file) | Single unified explanation of the entire project with cross-references to all other docs | Everyone | 25 min |

### Other Important Files

| File | Purpose |
|------|---------|
| [PROJECT_SUMMARY.txt](./PROJECT_SUMMARY.txt) | Plain-text project completion report |
| [SecureApp-API.postman_collection.json](./SecureApp-API.postman_collection.json) | Importable Postman collection with test scripts |
| [init-database.sql](./init-database.sql) | Database schema + seed data + Spring Session tables |
| `pom.xml` | Maven dependencies and build |
| `application.properties` | All runtime configuration |

### Recommended Reading Order

**New developer joining the team:**
```
1. SECUREAPP_COMPLETE_GUIDE.md    ← You are here (understand everything)
2. README.md                     ← Set up and run the app
3. SECURITY_IMPLEMENTATION.md    ← Deep-dive into security
4. DEVELOPER_QUICK_REFERENCE.md  ← Code patterns for new endpoints
5. TESTING_AND_SECURITY_CONCEPTS_GUIDE.md  ← Test your changes
```

**DevOps engineer:**
```
1. SECUREAPP_COMPLETE_GUIDE.md    ← Understand the project
2. SECURITY_CONFIGURATION_MATRIX.md ← All configs in lookup tables
3. IMPLEMENTATION_VALIDATION.md   ← Deployment checklist + monitoring
```

**QA tester:**
```
1. SECUREAPP_COMPLETE_GUIDE.md    ← Understand the project
2. TESTING_AND_SECURITY_CONCEPTS_GUIDE.md ← Every test scenario
3. IMPLEMENTATION_VALIDATION.md   ← Test checklists
```

---

## Summary

SecureApp is an **11-layer defense-in-depth** Spring Boot application. Every request passes through CORS → security headers → CSRF → session validation → authentication → URL authorization → interceptor authorization → method authorization → input validation before reaching business logic.

### Key Numbers

| Metric | Value |
|--------|-------|
| Java source files | 24 |
| Documentation files | 10 |
| API endpoints | 7 (3 public, 4 protected) |
| Security headers per response | 8 |
| Defense layers | 11 |
| Session timeout | 15 minutes |
| BCrypt strength | 12 (4,096 rounds) |
| Max sessions per user | 1 |
| Roles supported | 3 (USER, ADMIN, MODERATOR) |
| Database tables | 5 (users, roles, user_roles, SPRING_SESSION, SPRING_SESSION_ATTRIBUTES) |

---

**Created**: March 11, 2026
**Project**: SecureApp - Spring Boot 4.0.3 / Java 21
**Version**: 1.0.0
**Status**: Production Ready
