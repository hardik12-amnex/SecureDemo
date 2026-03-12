# SecureApp — Complete Testing & Security Concepts Guide

> **Purpose**: This guide walks you through how to test every part of the SecureApp project — from initial setup to verifying each security feature in action. It also explains the **"why"** behind each security concept so that you understand what you're testing and what each layer protects against.

---

## Table of Contents

1. [Prerequisites and Environment Setup](#1-prerequisites-and-environment-setup)
2. [Starting the Application](#2-starting-the-application)
3. [Testing with cURL (Command Line)](#3-testing-with-curl-command-line)
4. [Testing with Postman](#4-testing-with-postman)
5. [Testing with a Browser (DevTools)](#5-testing-with-a-browser-devtools)
6. [Security Concepts and How to Verify Them](#6-security-concepts-and-how-to-verify-them)
   - 6.1 [Session-Based Authentication](#61-session-based-authentication)
   - 6.2 [CSRF Protection](#62-csrf-protection)
   - 6.3 [CORS Policy](#63-cors-policy)
   - 6.4 [Security Headers](#64-security-headers)
   - 6.5 [Cookie Security Flags](#65-cookie-security-flags)
   - 6.6 [Password Hashing with BCrypt](#66-password-hashing-with-bcrypt)
   - 6.7 [Role-Based Access Control RBAC](#67-role-based-access-control-rbac)
   - 6.8 [Session Timeout and Invalidation](#68-session-timeout-and-invalidation)
   - 6.9 [Concurrent Session Control](#69-concurrent-session-control)
   - 6.10 [Input Validation](#610-input-validation)
7. [End-to-End Test Scenarios](#7-end-to-end-test-scenarios)
8. [Negative and Penetration-Style Tests](#8-negative-and-penetration-style-tests)
9. [Automated Testing Unit and Integration](#9-automated-testing-unit-and-integration)
10. [Troubleshooting Common Test Failures](#10-troubleshooting-common-test-failures)
11. [Quick Cheat Sheet](#11-quick-cheat-sheet)

---

## 1. Prerequisites and Environment Setup

Before running any tests, make sure the following services are up and configured:

| Dependency   | Required Version | Check Command                          |
|-------------|------------------|----------------------------------------|
| Java JDK    | 21+              | `java -version`                        |
| Maven       | 3.9.12+          | `mvn --version`                        |
| PostgreSQL  | 12+              | `psql --version`                       |
| cURL        | any              | `curl --version`                       |
| Postman     | latest (optional) | Download from https://www.postman.com |

### 1.1 Database Setup

```bash
# Connect to PostgreSQL
psql -U postgres -h localhost

# Create the database
CREATE DATABASE secureapp_db;

# Exit psql
\q

# Run the init script
psql -U postgres -h localhost -d secureapp_db -f init-database.sql
```

This script creates:
- `roles` table (ROLE_USER, ROLE_ADMIN, ROLE_MODERATOR)
- `users` table
- `user_roles` junction table
- `SPRING_SESSION` and `SPRING_SESSION_ATTRIBUTES` tables (for JDBC session store)
- Pre-seeded admin and test users with BCrypt-hashed passwords

### 1.2 Application Properties

Open `src/main/resources/application.properties` and verify:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/secureapp_db
spring.datasource.username=postgres
spring.datasource.password=postgres    # ← Change to your password
```

> **Tip**: For local testing, set `server.servlet.session.cookie.secure=false` so cookies work over HTTP (without HTTPS). In production, this must be `true`.

---

## 2. Starting the Application

```bash
# Navigate to the project root
cd E:\Projects\Agristack\poc\SecureDemo

# Clean build
mvn clean compile

# Package the JAR
mvn package -DskipTests

# Run the application
java -jar target/secureapp-1.0.0.jar
```

Or use Maven directly:

```bash
mvn spring-boot:run
```

The app starts at: **http://localhost:8080/api**

### Verify the App is Running

```bash
curl http://localhost:8080/api/health
```

Expected response:
```json
{
  "success": true,
  "message": "Service is healthy",
  "statusCode": 200,
  "data": {
    "status": "UP",
    "timestamp": 1741689600000
  }
}
```

✅ If you see this, the application is ready for testing.

---

## 3. Testing with cURL (Command Line)

cURL is the fastest way to test every endpoint. Follow the steps **in order** — each step builds on the previous one.

### 3.1 Health Check (Public Endpoint — No Auth Required)

```bash
curl -v http://localhost:8080/api/health
```

**What to verify:**
- HTTP status: `200 OK`
- No authentication required
- Security headers are present in the response headers (check the `-v` verbose output)

---

### 3.2 Register a New User

```bash
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser\",\"email\":\"test@example.com\",\"firstName\":\"Test\",\"lastName\":\"User\",\"password\":\"SecurePass123!\",\"confirmPassword\":\"SecurePass123!\"}"
```

Expected response (`201 Created`):
```json
{
  "success": true,
  "message": "User registered successfully",
  "statusCode": 201,
  "data": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "roles": ["ROLE_USER"]
  }
}
```

**What to verify:**
- Status code is `201`
- User gets `ROLE_USER` by default
- Password is NOT returned in the response (security best practice)

---

### 3.3 Register Duplicate User (Negative Test)

```bash
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser\",\"email\":\"test@example.com\",\"firstName\":\"Test\",\"lastName\":\"User\",\"password\":\"SecurePass123!\",\"confirmPassword\":\"SecurePass123!\"}"
```

Expected response (`400 Bad Request`):
```json
{
  "success": false,
  "message": "Username already exists",
  "statusCode": 400
}
```

---

### 3.4 Login (Creates a Session)

```bash
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies.txt ^
  -v ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"
```

**What to verify:**
- Status code: `200 OK`
- A `Set-Cookie` header with `JSESSIONID` is returned
- The cookie has flags: `HttpOnly`, `Secure`, `SameSite=Strict`
- The `cookies.txt` file now contains the session cookie
- A `XSRF-TOKEN` cookie may also be set (for CSRF protection)

---

### 3.5 Access Protected Endpoint (With Session)

```bash
curl -X GET http://localhost:8080/api/dashboard ^
  -b cookies.txt ^
  -v
```

Expected response (`200 OK`):
```json
{
  "success": true,
  "message": "Dashboard data fetched",
  "statusCode": 200,
  "data": {
    "message": "Welcome to dashboard, testuser"
  }
}
```

---

### 3.6 Access Protected Endpoint (Without Session — Negative Test)

```bash
curl -X GET http://localhost:8080/api/dashboard -v
```

Expected response (`401 Unauthorized`):
- Proves that unauthenticated users cannot access protected resources

---

### 3.7 Access Admin Endpoint as Regular User (Negative Test)

```bash
curl -X GET http://localhost:8080/api/admin/users ^
  -b cookies.txt ^
  -v
```

Expected response (`403 Forbidden`):
- Proves RBAC is working — `ROLE_USER` cannot access admin endpoints

---

### 3.8 Get Current User Profile

```bash
curl -X GET http://localhost:8080/api/auth/me ^
  -b cookies.txt
```

Expected response: Current user details.

---

### 3.9 Logout

```bash
curl -X POST http://localhost:8080/api/auth/logout ^
  -b cookies.txt ^
  -c cookies.txt ^
  -v
```

**What to verify:**
- `JSESSIONID` cookie is deleted (max-age=0 or removed)
- Session is invalidated on the server

---

### 3.10 Access Protected Endpoint After Logout (Negative Test)

```bash
curl -X GET http://localhost:8080/api/dashboard ^
  -b cookies.txt ^
  -v
```

Expected: `401 Unauthorized` — session was destroyed, access denied.

---

## 4. Testing with Postman

### 4.1 Import the Collection

1. Open Postman
2. Click **Import** → select `SecureApp-API.postman_collection.json` from the project root
3. Set the environment variable `base_url` to `http://localhost:8080/api`

### 4.2 Recommended Test Order

Run requests in this order:

| # | Request | Expected Status | Purpose |
|---|---------|----------------|---------|
| 1 | Health Check | 200 | Verify app is up |
| 2 | Register User | 201 | Create a test account |
| 3 | Register Duplicate | 400 | Validate uniqueness |
| 4 | Login | 200 | Start a session |
| 5 | Get Current User (/me) | 200 | Verify session works |
| 6 | Dashboard | 200 | Test authenticated access |
| 7 | Admin Users (as USER) | 403 | Test RBAC |
| 8 | Logout | 200 | End the session |
| 9 | Dashboard (after logout) | 401 | Verify session destroyed |

### 4.3 Postman Tips for Session-Based Auth

- **Cookies are auto-managed**: Postman automatically stores the `JSESSIONID` cookie after login and sends it with subsequent requests.
- **CSRF Token**: If CSRF is enabled, after login look for the `XSRF-TOKEN` cookie. Add a header `X-XSRF-TOKEN` with that cookie's value to all POST/PUT/DELETE requests.
- **Disable auto-redirects**: Go to Postman Settings → disable "Automatically follow redirects" for better visibility.

### 4.4 Inspecting Cookies in Postman

1. After login, click the **Cookies** link (below the Send button)
2. Look for domain `localhost`
3. You should see:
   - `JSESSIONID` — your session ID
   - `XSRF-TOKEN` — CSRF protection token (if CSRF is enabled)

---

## 5. Testing with a Browser (DevTools)

### 5.1 Checking Security Headers

1. Open browser → navigate to `http://localhost:8080/api/health`
2. Open DevTools (F12) → go to **Network** tab
3. Click on the request → go to **Response Headers**
4. Verify the following headers:

| Header | Expected Value |
|--------|---------------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; ...` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `accelerometer=(), camera=(), ...` |
| `Cache-Control` | `no-store, no-cache, must-revalidate, max-age=0` |

### 5.2 Checking Cookie Flags

1. DevTools → **Application** tab → **Cookies** → `http://localhost:8080`
2. Find `JSESSIONID` and verify:

| Flag | Expected | Purpose |
|------|----------|---------|
| HttpOnly | ✅ Yes | JavaScript cannot read the cookie |
| Secure | ✅ Yes | Cookie only sent over HTTPS |
| SameSite | Strict | Cookie not sent in cross-site requests |
| Path | / | Available for all paths |

---

## 6. Security Concepts and How to Verify Them

### 61 Session-Based Authentication

#### 💡 Concept
Instead of sending credentials (like a JWT) with every request, the server creates a **session** after login and gives the browser a **session ID** (stored in a cookie). On each subsequent request, the browser sends the cookie, and the server looks up the session to identify the user.

#### 🔒 Why it's secure
- Session data lives on the **server side** (PostgreSQL database via JDBC) — the client only has a meaningless ID
- No sensitive data is exposed to the client
- Sessions can be immediately invalidated (unlike JWTs that remain valid until they expire)

#### ✅ How to test

```bash
# Step 1: Login and save cookies
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies.txt ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# Step 2: Use the session cookie to access protected resource
curl -X GET http://localhost:8080/api/dashboard -b cookies.txt
# → 200 OK ✅

# Step 3: Try WITHOUT the cookie
curl -X GET http://localhost:8080/api/dashboard
# → 401 Unauthorized ✅

# Step 4: Try with a FAKE session ID
curl -X GET http://localhost:8080/api/dashboard ^
  -H "Cookie: JSESSIONID=fakesessionid12345"
# → 401 Unauthorized ✅ (server doesn't recognize fake IDs)
```

---

### 62 CSRF Protection

#### 💡 Concept
**Cross-Site Request Forgery (CSRF)** is an attack where a malicious website tricks your browser into making requests to our app using your existing session cookie. For example, a hidden form on `evil.com` could submit a POST request to `/api/auth/logout` — and your browser would automatically send the JSESSIONID cookie.

#### 🔒 How we prevent it
- Spring Security generates a **CSRF token** and stores it in a cookie (`XSRF-TOKEN`)
- All state-changing requests (POST, PUT, DELETE, PATCH) must include this token in the `X-XSRF-TOKEN` header
- The server validates the token — if it doesn't match, the request is rejected

#### ✅ How to test

```bash
# Step 1: Login and check for XSRF-TOKEN cookie
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies.txt -v ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"
# Look for: Set-Cookie: XSRF-TOKEN=<token_value>

# Step 2: Make a POST request WITHOUT CSRF token
curl -X POST http://localhost:8080/api/auth/logout ^
  -b cookies.txt -v
# → 403 Forbidden ✅ (CSRF token missing)

# Step 3: Make the same request WITH the CSRF token
curl -X POST http://localhost:8080/api/auth/logout ^
  -b cookies.txt ^
  -H "X-XSRF-TOKEN: <token_value_from_step_1>" ^
  -v
# → 200 OK ✅
```

> **Note**: GET requests don't require CSRF tokens because they should be idempotent (read-only).

---

### 63 CORS Policy

#### 💡 Concept
**Cross-Origin Resource Sharing (CORS)** controls which websites can make AJAX requests to your API. Without CORS, any website could call your API from the browser.

#### 🔒 Our configuration
- Only `http://localhost:4200` (Angular frontend) is allowed
- Credentials (cookies) are allowed in cross-origin requests
- Preflight cache: 1 hour

#### ✅ How to test

```bash
# Test 1: Preflight request from ALLOWED origin
curl -X OPTIONS http://localhost:8080/api/dashboard ^
  -H "Origin: http://localhost:4200" ^
  -H "Access-Control-Request-Method: GET" ^
  -v
# → Response should include:
#   Access-Control-Allow-Origin: http://localhost:4200
#   Access-Control-Allow-Credentials: true

# Test 2: Request from DISALLOWED origin
curl -X OPTIONS http://localhost:8080/api/dashboard ^
  -H "Origin: http://evil-site.com" ^
  -H "Access-Control-Request-Method: GET" ^
  -v
# → No Access-Control-Allow-Origin header (request blocked by browser)
```

---

### 64 Security Headers

#### 💡 Concept
Security headers tell the browser how to behave when handling your content. They add defense-in-depth layers against XSS, clickjacking, MIME-sniffing, and other attacks.

#### Headers in this project

| Header | What it prevents | Simple explanation |
|--------|-----------------|-------------------|
| `Content-Security-Policy` | XSS attacks | "Only load scripts/styles from our own domain" |
| `X-Frame-Options: DENY` | Clickjacking | "Don't allow our pages to be embedded in iframes" |
| `X-Content-Type-Options: nosniff` | MIME confusion attacks | "Don't guess the file type — use what we declared" |
| `Strict-Transport-Security` | Downgrade attacks | "Always use HTTPS, even if user types HTTP" |
| `X-XSS-Protection` | Reflected XSS (legacy) | "Browser, block the page if you detect an XSS attack" |
| `Referrer-Policy` | Data leakage | "Don't send full URL to other sites" |
| `Permissions-Policy` | Feature abuse | "Disable camera, microphone, geolocation, etc." |
| `Cache-Control: no-store` | Sensitive data caching | "Never cache these responses" |

#### ✅ How to test

```bash
curl -v http://localhost:8080/api/health 2>&1 | findstr /i "Content-Security X-Frame X-Content Strict-Transport X-XSS Referrer Permissions Cache-Control"
```

You should see all headers listed above in the response.

---

### 65 Cookie Security Flags

#### 💡 Concept
Cookies carry your session ID. If an attacker can steal or misuse this cookie, they can hijack your session. Cookie flags are the defense.

| Flag | What it does | Attack it prevents |
|------|-------------|-------------------|
| `HttpOnly` | JavaScript can't read the cookie | XSS-based cookie theft |
| `Secure` | Cookie only sent over HTTPS | Network sniffing / Man-in-the-Middle |
| `SameSite=Strict` | Cookie not sent in cross-site requests | CSRF attacks |
| `Max-Age=900` | Cookie expires after 15 minutes | Long-lived session abuse |

#### ✅ How to test

```bash
# Login and check Set-Cookie header
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies.txt -v ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# In the response headers, look for:
# Set-Cookie: JSESSIONID=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900
```

Test that `HttpOnly` works:
1. Open browser DevTools → Console
2. Type: `document.cookie`
3. `JSESSIONID` should **NOT** appear (HttpOnly prevents JS access)

---

### 66 Password Hashing with BCrypt

#### 💡 Concept
Passwords are **never stored in plain text**. We use **BCrypt** with a strength of 12, which means:
- The password is hashed using a one-way function
- Even if the database is compromised, attackers can't reverse the hash
- The strength factor (12) means 2^12 = 4096 hashing rounds, making brute-force slow

#### ✅ How to test

```sql
-- Connect to PostgreSQL and check stored passwords
psql -U postgres -d secureapp_db -c "SELECT username, password FROM users;"
```

You should see something like:
```
 username  |                           password
-----------+--------------------------------------------------------------
 testuser  | $2a$12$K8GpVxLZ2f5mBjQpT1qRbe.JxR0fGjKm5Y3z7J...
```

- The password starts with `$2a$12$` — confirming BCrypt with strength 12
- The stored hash is 60 characters long
- Two users with the same password will have **different** hashes (due to salt)

---

### 67 Role-Based Access Control RBAC

#### 💡 Concept
Different users have different permissions. A regular user should NOT be able to access admin functionality. This is enforced at two levels:

1. **URL-level**: In `SecurityConfig.java` → `authorizeHttpRequests()`
2. **Method-level**: Using `@PreAuthorize("hasRole('ADMIN')")` on controller methods

#### 🔑 Roles in this project
| Role | Access Level |
|------|-------------|
| `ROLE_USER` | Standard user — can access `/dashboard`, `/auth/me` |
| `ROLE_ADMIN` | Administrator — can access `/admin/users` and all user endpoints |

#### ✅ How to test

```bash
# Step 1: Login as a regular USER
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c user_cookies.txt ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# Step 2: Access user endpoint → should SUCCEED
curl -X GET http://localhost:8080/api/dashboard -b user_cookies.txt
# → 200 OK ✅

# Step 3: Access admin endpoint → should FAIL
curl -X GET http://localhost:8080/api/admin/users -b user_cookies.txt
# → 403 Forbidden ✅

# Step 4: Login as ADMIN (use pre-seeded admin from init-database.sql)
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c admin_cookies.txt ^
  -d "{\"username\":\"admin\",\"password\":\"Admin@123\"}"

# Step 5: Access admin endpoint as ADMIN → should SUCCEED
curl -X GET http://localhost:8080/api/admin/users -b admin_cookies.txt
# → 200 OK ✅
```

---

### 68 Session Timeout and Invalidation

#### 💡 Concept
Sessions automatically expire after **15 minutes** of inactivity. This protects against:
- Abandoned sessions on shared computers
- Session hijacking with stale tokens

#### ✅ How to test

```bash
# Step 1: Login
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies.txt ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# Step 2: Immediately access dashboard → works
curl -X GET http://localhost:8080/api/dashboard -b cookies.txt
# → 200 OK

# Step 3: Wait 15+ minutes, then try again
# (Or temporarily change server.servlet.session.timeout=1m in application.properties for faster testing)

curl -X GET http://localhost:8080/api/dashboard -b cookies.txt
# → 401 Unauthorized ✅ (session expired)
```

> **Quick Test Tip**: Change `server.servlet.session.timeout=1m` and `server.servlet.session.cookie.max-age=60` in `application.properties` for faster timeout testing. Don't forget to revert!

---

### 69 Concurrent Session Control

#### 💡 Concept
Each user is limited to **1 active session** at a time. If a user logs in from a second browser/device, the first session is invalidated. This prevents:
- Account sharing
- Stolen session usage alongside the legitimate user

#### ✅ How to test

```bash
# Step 1: Login from "Browser A"
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies_a.txt ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# Step 2: Login from "Browser B" (same user)
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -c cookies_b.txt ^
  -d "{\"username\":\"testuser\",\"password\":\"SecurePass123!\"}"

# Step 3: Try "Browser A" session → should be invalidated
curl -X GET http://localhost:8080/api/dashboard -b cookies_a.txt
# → 401 Unauthorized ✅ (old session replaced)

# Step 4: "Browser B" session → should work
curl -X GET http://localhost:8080/api/dashboard -b cookies_b.txt
# → 200 OK ✅
```

---

### 610 Input Validation

#### 💡 Concept
All user inputs are validated using Jakarta Bean Validation annotations (`@NotBlank`, `@Email`, `@Size`, etc.). Invalid data is rejected with clear error messages before reaching the business logic.

#### ✅ How to test

```bash
# Test 1: Empty username
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"\",\"email\":\"a@b.com\",\"firstName\":\"A\",\"lastName\":\"B\",\"password\":\"Pass123!\",\"confirmPassword\":\"Pass123!\"}"
# → 400 Bad Request with validation error message

# Test 2: Invalid email format
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"user2\",\"email\":\"not-an-email\",\"firstName\":\"A\",\"lastName\":\"B\",\"password\":\"Pass123!\",\"confirmPassword\":\"Pass123!\"}"
# → 400 Bad Request

# Test 3: Password mismatch
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"user3\",\"email\":\"u3@b.com\",\"firstName\":\"A\",\"lastName\":\"B\",\"password\":\"Pass123!\",\"confirmPassword\":\"Different!\"}"
# → 400 Bad Request

# Test 4: Missing required fields
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{}"
# → 400 Bad Request with list of validation errors
```

---

## 7. End-to-End Test Scenarios

### Scenario 1: Complete User Lifecycle

```
1. Register user          → POST /api/auth/register   → 201
2. Login                  → POST /api/auth/login      → 200 + JSESSIONID cookie
3. Access dashboard       → GET  /api/dashboard       → 200
4. Get profile            → GET  /api/auth/me         → 200
5. Logout                 → POST /api/auth/logout     → 200
6. Access dashboard again → GET  /api/dashboard       → 401
```

### Scenario 2: Admin Workflow

```
1. Login as admin         → POST /api/auth/login      → 200
2. Access admin panel     → GET  /api/admin/users     → 200
3. Access user dashboard  → GET  /api/dashboard       → 200
4. Logout                 → POST /api/auth/logout     → 200
```

### Scenario 3: Unauthorized Access Attempt

```
1. Access dashboard (no login)    → GET /api/dashboard    → 401
2. Access admin (no login)        → GET /api/admin/users  → 401
3. Login as regular user          → POST /api/auth/login  → 200
4. Access admin (as ROLE_USER)    → GET /api/admin/users  → 403
```

### Scenario 4: Session Expiry

```
1. Login                          → 200 + session
2. Wait for session timeout (15 min)
3. Access dashboard               → 401 (session expired)
4. Re-login                       → 200 + new session
5. Access dashboard               → 200 (new session works)
```

---

## 8. Negative and Penetration-Style Tests

These tests simulate attack scenarios. **All should fail**, proving that security is working.

### Test 1: Session Hijacking (Fake Session ID)
```bash
curl -X GET http://localhost:8080/api/dashboard ^
  -H "Cookie: JSESSIONID=aaaa-bbbb-cccc-dddd-fake" -v
# Expected: 401 Unauthorized
```

### Test 2: Accessing API Without Context Path
```bash
curl -X GET http://localhost:8080/dashboard -v
# Expected: 404 Not Found (context path is /api)
```

### Test 3: SQL Injection in Login
```bash
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"' OR 1=1 --\",\"password\":\"anything\"}"
# Expected: 401 Unauthorized (JPA uses parameterized queries — immune to SQL injection)
```

### Test 4: XSS in Registration
```bash
curl -X POST http://localhost:8080/api/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"<script>alert(1)</script>\",\"email\":\"x@y.com\",\"firstName\":\"A\",\"lastName\":\"B\",\"password\":\"Pass123!\",\"confirmPassword\":\"Pass123!\"}"
# Expected: 400 (validation rejects it) or the script is stored as plain text (never executed due to CSP)
```

### Test 5: Access After Logout
```bash
# Save JSESSIONID before logout, then try using it after logout
curl -X GET http://localhost:8080/api/dashboard ^
  -H "Cookie: JSESSIONID=<old_session_id>" -v
# Expected: 401 Unauthorized (session invalidated)
```

### Test 6: Cross-Origin Request
```bash
curl -X GET http://localhost:8080/api/dashboard ^
  -H "Origin: http://malicious-site.com" -v
# Expected: No Access-Control-Allow-Origin header → browser would block this
```

---

## 9. Automated Testing Unit and Integration

### 9.1 Unit Test Example — SecurityConfig

Create `src/test/java/com/example/secureapp/config/SecurityConfigTest.java`:

```java
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthEndpoint_shouldBePublic() throws Exception {
        mockMvc.perform(get("/api/health"))
               .andExpect(status().isOk());
    }

    @Test
    void dashboardEndpoint_shouldRequireAuth() throws Exception {
        mockMvc.perform(get("/api/dashboard"))
               .andExpect(status().isUnauthorized());
    }

    @Test
    void adminEndpoint_shouldRequireAdminRole() throws Exception {
        mockMvc.perform(get("/api/admin/users")
               .with(user("testuser").roles("USER")))
               .andExpect(status().isForbidden());
    }

    @Test
    void adminEndpoint_shouldAllowAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users")
               .with(user("admin").roles("ADMIN")))
               .andExpect(status().isOk());
    }
}
```

### 9.2 Integration Test — Auth Flow

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void fullAuthFlow() throws Exception {
        // Register
        mockMvc.perform(post("/api/auth/register")
               .contentType(MediaType.APPLICATION_JSON)
               .content("{\"username\":\"flowuser\",\"email\":\"flow@test.com\"," +
                        "\"firstName\":\"Flow\",\"lastName\":\"User\"," +
                        "\"password\":\"Test123!\",\"confirmPassword\":\"Test123!\"}"))
               .andExpect(status().isCreated());

        // Login
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
               .contentType(MediaType.APPLICATION_JSON)
               .content("{\"username\":\"flowuser\",\"password\":\"Test123!\"}"))
               .andExpect(status().isOk())
               .andReturn();

        // Extract session cookie
        String sessionCookie = loginResult.getResponse().getHeader("Set-Cookie");

        // Access protected endpoint with session
        mockMvc.perform(get("/api/dashboard")
               .header("Cookie", sessionCookie))
               .andExpect(status().isOk());
    }
}
```

### 9.3 Run Tests

```bash
mvn test
```

---

## 10. Troubleshooting Common Test Failures

| Problem | Cause | Solution |
|---------|-------|----------|
| `Connection refused` on port 8080 | App not running | Start the app with `mvn spring-boot:run` |
| `401` on login | Wrong credentials | Check username/password; check database has the user |
| `403` on POST requests | Missing CSRF token | Include `X-XSRF-TOKEN` header |
| `401` on protected endpoints | No/expired session cookie | Login first and use `-b cookies.txt` |
| `500 Internal Server Error` | Database not connected | Check PostgreSQL is running; check `application.properties` |
| Cookie not set | `Secure=true` over HTTP | Set `server.servlet.session.cookie.secure=false` for local HTTP testing |
| CORS errors in browser | Wrong origin | Use `http://localhost:4200` or update `SecurityConfig.java` |
| Session expires too fast | Timeout misconfiguration | Check `server.servlet.session.timeout` value |

---

## 11. Quick Cheat Sheet

### Endpoints Summary

| Method | Endpoint | Auth Required | Role Required | Purpose |
|--------|----------|:------------:|:------------:|---------|
| GET | `/api/health` | ❌ | — | Health check |
| POST | `/api/auth/register` | ❌ | — | Register new user |
| POST | `/api/auth/login` | ❌ | — | Login & get session |
| POST | `/api/auth/logout` | ✅ | — | Destroy session |
| GET | `/api/auth/me` | ✅ | — | Get current user |
| GET | `/api/dashboard` | ✅ | ROLE_USER | User dashboard |
| GET | `/api/admin/users` | ✅ | ROLE_ADMIN | Admin only |

### Security Layers (Defense in Depth)

```
┌────────────────────────────────────────────────────────────┐
│                      CLIENT (Browser)                       │
├────────────────────────────────────────────────────────────┤
│  CORS Policy        → Only localhost:4200 allowed           │
├────────────────────────────────────────────────────────────┤
│  HTTPS + HSTS       → Encrypted transport                   │
├────────────────────────────────────────────────────────────┤
│  Cookie Flags       → HttpOnly, Secure, SameSite=Strict     │
├────────────────────────────────────────────────────────────┤
│  CSRF Token         → Blocks cross-site form submissions     │
├────────────────────────────────────────────────────────────┤
│  Security Headers   → CSP, X-Frame-Options, nosniff, etc.   │
├────────────────────────────────────────────────────────────┤
│  Session Validation → Valid session required for protected   │
├────────────────────────────────────────────────────────────┤
│  Authentication     → Username/password → BCrypt verify      │
├────────────────────────────────────────────────────────────┤
│  Authorization      → RBAC: ROLE_USER, ROLE_ADMIN            │
├────────────────────────────────────────────────────────────┤
│  Input Validation   → Jakarta Bean Validation                │
├────────────────────────────────────────────────────────────┤
│  SQL Injection      → JPA parameterized queries              │
├────────────────────────────────────────────────────────────┤
│                     DATABASE (PostgreSQL)                     │
└────────────────────────────────────────────────────────────┘
```

### Key Files for Security

| File | Purpose |
|------|---------|
| `SecurityConfig.java` | Main security filter chain, CORS, CSRF, authorization rules |
| `SessionConfig.java` | JDBC session store (PostgreSQL), timeout |
| `WebMvcConfig.java` | Registers AuthorizationInterceptor into MVC chain |
| `SecurityHeadersFilter.java` | Custom HTTP security headers (8 headers) |
| `SessionValidationFilter.java` | Validates session exists and is authenticated |
| `AuthorizationInterceptor.java` | MVC interceptor — role-based path authorization |
| `RolePermissionMapping.java` | Centralized role-to-path permission map |
| `CustomUserDetailsService.java` | Loads user from DB for Spring Security |
| `SecurityUtils.java` | Static thread-safe utilities for SecurityContext access |
| `SecurityUtil.java` | Request-level utilities (client IP, HTTPS detection) |
| `application.properties` | Cookie flags, session timeout, database config |

---

**Created**: March 11, 2026  
**Project**: SecureApp — Spring Boot 4.0.3  
**Version**: 1.0.0
