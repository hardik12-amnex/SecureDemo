# Threat Analysis & Security Hardening Report — SecureApp

**Date:** March 17, 2026  
**Project:** Agristack Secure Application — Java Spring Boot Backend (POC)  
**Version:** 2.0.0 (Stateless JWT + HttpOnly Cookie + DPoP)  
**Author:** Security analysis of the SecureApp POC

---

## Purpose

This document identifies **every known attack vector** against the current SecureApp implementation, categorises threats by severity, explains the attacker's methodology, and documents whether the threat has been **mitigated**, **partially mitigated**, or **remains a risk**. Where possible, code-level fixes have been implemented and are referenced.

---

## Current Security Architecture Summary

```
Client (Browser)
  │
  ├── ECDSA P-256 private key (in memory — never transmitted)
  ├── DPoP proof JWT (signed with private key, sent in DPoP header)
  ├── ACCESS_TOKEN cookie (HttpOnly, Secure, SameSite=Strict — auto-attached)
  └── XSRF-TOKEN cookie (readable by JS — sent as X-XSRF-TOKEN header)
  │
  ▼
Server (Spring Boot — Stateless)
  ├── JwtAuthenticationFilter   → Reads JWT from HttpOnly cookie
  ├── DPoPAuthenticationFilter  → Validates DPoP proof, matches JWT-bound thumbprint
  ├── CSRF Filter               → Validates X-XSRF-TOKEN for state-changing requests
  ├── AuthorizationInterceptor  → Role-based path authorization
  ├── @PreAuthorize             → Method-level security
  └── SecurityHeadersFilter     → CSP, HSTS, X-Frame-Options, etc.
```

---

## Threat Matrix

| # | Threat | Severity | Status | Details |
|---|--------|----------|--------|---------|
| 1 | XSS — Token Theft | CRITICAL | ✅ MITIGATED | HttpOnly cookie — JS cannot access token |
| 2 | XSS — DPoP Private Key Theft | HIGH | ⚠️ PARTIAL | CSP headers block most XSS; WebCrypto non-exportable keys help, but not bulletproof |
| 3 | CSRF Attack | HIGH | ✅ MITIGATED | CookieCsrfTokenRepository + SameSite=Strict + DPoP |
| 4 | JWT Token Theft (Network) | HIGH | ✅ MITIGATED | DPoP binding — token useless without private key |
| 5 | JWT Token Tampering | HIGH | ✅ MITIGATED | HMAC-SHA512 signature — any change invalidates token |
| 6 | Brute-Force Login | HIGH | ⚠️ RISK | No rate limiting implemented — unlimited attempts possible |
| 7 | Account Enumeration | MEDIUM | ✅ FIXED | Generic "Invalid credentials" for all login failures |
| 8 | DPoP Proof Replay | HIGH | ✅ MITIGATED | jti cache + iat window validation |
| 9 | Weak Password | MEDIUM | ✅ FIXED | Regex pattern enforces uppercase + lowercase + digit + special char |
| 10 | Server-Side Secret Compromise | CRITICAL | ⚠️ RISK | JWT secret in plaintext properties file |
| 11 | Clickjacking | MEDIUM | ✅ MITIGATED | X-Frame-Options: DENY + frame-ancestors 'none' |
| 12 | CORS Bypass | MEDIUM | ✅ MITIGATED | Strict origin whitelist (localhost:4200 only) |
| 13 | SQL Injection | HIGH | ✅ MITIGATED | JPA parameterized queries — no raw SQL |
| 14 | Stack Trace Leakage | LOW | ✅ FIXED | `include-stacktrace=never` + `include-message=never` |
| 15 | DPoP Replay in Multi-Instance | MEDIUM | ⚠️ RISK | In-memory Caffeine cache — not shared across instances |
| 16 | Phishing / Credential Theft | HIGH | ⚠️ RISK | No MFA implemented |
| 17 | Client Malware | CRITICAL | ❌ OUTSIDE SCOPE | Full device compromise — app cannot defend |
| 18 | JWT Non-Revocability | MEDIUM | ⚠️ RISK | No token blacklist — stolen JWT valid until expiry |
| 19 | Timing Attack on Auth | LOW | ✅ MITIGATED | BCrypt.matches() is constant-time |
| 20 | MIME Sniffing | LOW | ✅ MITIGATED | X-Content-Type-Options: nosniff |

---

## Detailed Threat Analysis

---

### THREAT 1: XSS — Token Theft via JavaScript

**Severity:** CRITICAL  
**Status:** ✅ MITIGATED

**Attack Method:**  
Attacker injects malicious JavaScript (stored XSS, reflected XSS, or DOM-based XSS) to steal the JWT token using `document.cookie` or by intercepting the `Authorization` header.

**Why Our Application Is Protected:**
- JWT is stored in an **HttpOnly cookie** — `document.cookie` cannot read it
- `Content-Security-Policy: script-src 'self'` blocks inline and external scripts
- `X-XSS-Protection: 1; mode=block` provides legacy browser protection
- Token is **never exposed in the response body** — only set via `Set-Cookie` header

**Residual Risk:**  
If CSP is misconfigured or bypassed (e.g., via a whitelisted CDN hosting malicious scripts), XSS could still execute. However, even successful XSS **cannot steal the JWT token** because of the HttpOnly flag.

---

### THREAT 2: XSS — DPoP Private Key Theft via WebCrypto

**Severity:** HIGH  
**Status:** ⚠️ PARTIALLY MITIGATED

**Attack Method:**  
Even though the JWT cookie is HttpOnly, if an attacker achieves XSS, they could potentially:
1. Access the DPoP private key if it's stored as an exportable `CryptoKey` in the browser
2. Use the `crypto.subtle.sign()` API to sign DPoP proofs directly from the compromised page
3. Make authenticated requests from within the victim's browser context

**Why Our Application Partially Protects:**
- CSP headers (`script-src 'self'`) block most XSS injection vectors
- `frame-ancestors 'none'` prevents clickjacking-assisted XSS
- Security headers reduce the attack surface significantly

**What Is NOT Protected:**
- If XSS succeeds despite CSP, the attacker **runs code in the victim's browser** and can call `crypto.subtle.sign()` with the stored key
- The attacker doesn't need to *steal* the key — they can sign proofs directly from the compromised page

**Recommendation for Frontend (client-side):**
- Generate the ECDSA key pair with `extractable: false` in WebCrypto — this prevents the key from being exported, though the attacker can still *use* it via `sign()` if they have XSS
- Store the CryptoKey reference only in a closure or module-scoped variable, not in `window` or `localStorage`
- This is fundamentally a frontend responsibility

---

### THREAT 3: CSRF Attack

**Severity:** HIGH  
**Status:** ✅ MITIGATED

**Attack Method:**  
Attacker hosts a malicious website that submits a POST request to our API. Since the browser auto-attaches the `ACCESS_TOKEN` HttpOnly cookie, the request appears authenticated.

**Why Our Application Is Protected (3 layers):**
1. **CookieCsrfTokenRepository** — Every state-changing request requires a valid `X-XSRF-TOKEN` header. The attacker's site cannot read the `XSRF-TOKEN` cookie (cross-origin cookie access is blocked by the browser).
2. **SameSite=Strict cookie** — The `ACCESS_TOKEN` cookie is **never sent on cross-site requests** (including top-level navigations), which is the strictest SameSite policy.
3. **DPoP header** — Even if CSRF token is somehow bypassed, the attacker cannot produce a valid `DPoP` header because they don't have the client's private key.

**Implementation Reference:**
- `SecurityConfig.java` → `.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())`
- `AuthController.java` → `ResponseCookie.sameSite("Strict")`

---

### THREAT 4: JWT Token Theft via Network Interception

**Severity:** HIGH  
**Status:** ✅ MITIGATED

**Attack Method:**  
Attacker performs a Man-in-the-Middle (MITM) attack on the network (e.g., rogue WiFi, ARP spoofing) to intercept the `ACCESS_TOKEN` cookie.

**Why Our Application Is Protected:**
- Cookie has `Secure=true` — only transmitted over HTTPS
- `Strict-Transport-Security: max-age=31536000` forces HTTPS for 1 year
- Even if the cookie IS intercepted, DPoP makes it useless — the attacker cannot produce a valid DPoP proof without the client's private key

**Implementation Reference:**
- `AuthController.java` → `ResponseCookie.secure(true)`
- `SecurityHeadersFilter.java` → HSTS header
- `DPoPAuthenticationFilter.java` → Thumbprint comparison (lines 119-133)

---

### THREAT 5: JWT Token Tampering (Privilege Escalation)

**Severity:** HIGH  
**Status:** ✅ MITIGATED

**Attack Method:**  
Attacker decodes the JWT (base64), modifies claims (e.g., changes `roles` from `ROLE_USER` to `ROLE_ADMIN` or changes `dpop_jkt` to their own key's thumbprint), and re-encodes it.

**Why Our Application Is Protected:**
- JWT is signed with **HMAC-SHA512** using a 512-bit server-side secret
- Any modification to the payload invalidates the signature
- `JwtTokenService.validateAndGetClaims()` verifies the signature on every request
- The issuer claim (`iss: "secureapp"`) is also validated

**Implementation Reference:**
- `JwtTokenService.java` → `Jwts.SIG.HS512` signing
- `JwtAuthenticationFilter.java` → `jwtTokenService.validateAndGetClaims(token)`

**Important Note:**  
JWTs are **encoded, NOT encrypted**. Anyone can decode and read the claims. This is by design — the security comes from the **signature**, not secrecy of the payload. The `dpop_jkt` claim is a SHA-256 thumbprint (a hash), not the actual public key.

---

### THREAT 6: Brute-Force Login Attack

**Severity:** HIGH  
**Status:** ⚠️ RISK (not implemented)

**Attack Method:**  
Attacker automates login requests with common passwords or credential lists to guess a user's password. Without rate limiting, unlimited attempts are possible.

**Current Vulnerability:**  
No rate limiting or account lockout mechanism exists. An attacker can send unlimited login requests at maximum speed.

**Why DPoP Partially Mitigates This:**  
The attacker must still generate valid DPoP proofs for each request, adding computational overhead. However, ECDSA key generation and signing are fast operations, so this is not a meaningful barrier.

**Recommendations for Production:**
1. Implement **API-level rate limiting** (e.g., per-IP and per-username counters)
2. Add **account lockout** after N consecutive failed attempts (with auto-unlock after a cooldown period)
3. Use an **API gateway** (e.g., Kong, AWS API Gateway) or **WAF** (Web Application Firewall) with built-in rate limiting
4. Add **CAPTCHA** (e.g., reCAPTCHA v3) after N failed attempts to block automated tools
5. Implement **progressive delays** — increase response time after each failure

---

### THREAT 7: Account Enumeration

**Severity:** MEDIUM  
**Status:** ✅ FIXED

**Attack Method:**  
Attacker sends login requests with different usernames. If the error message differs between "User not found" and "Wrong password", the attacker can enumerate which usernames exist in the system.

**Previous Vulnerability:**  
`AuthService.login()` threw `ResourceNotFoundException("User not found")` for missing users but `BadRequestException("Invalid credentials")` for wrong passwords — different messages revealed account existence. Additionally, `"Account is disabled"` and `"Account is locked"` messages revealed account status.

**Fix Implemented:**
- All login failure paths now return the same generic message: `"Invalid credentials"`
- User not found, wrong password, disabled account, and locked account all produce identical responses
- Debug logs no longer leak password hash information

**Implementation Reference:**
- `AuthService.java` → All login failures throw `BadRequestException("Invalid credentials")`

---

### THREAT 8: DPoP Proof Replay Attack

**Severity:** HIGH  
**Status:** ✅ MITIGATED

**Attack Method:**  
Attacker intercepts a valid DPoP proof and replays it on a different request.

**Why Our Application Is Protected:**
- Each proof must contain a unique `jti` claim — tracked in Caffeine cache (100K entries, 300s TTL)
- `iat` claim validated within ±300 seconds — stale proofs rejected
- `htm` (method) and `htu` (URI) claims must match the actual request — proof cannot be reused for a different endpoint

**Implementation Reference:**
- `DPoPReplayProtectionService.java` → `isJtiUnique(jti)`
- `DPoPProofValidator.java` → iat, htm, htu validation

---

### THREAT 9: Weak Password Registration

**Severity:** MEDIUM  
**Status:** ✅ FIXED

**Attack Method:**  
Users register with weak passwords like `password`, `12345678`, or `qwertyui` — easily guessable via dictionary attacks.

**Previous Vulnerability:**  
Only minimum length (8 chars) was enforced. No complexity requirements.

**Fix Implemented:**
- `SignUpRequest.java` now enforces a regex pattern:
  - At least one **uppercase** letter
  - At least one **lowercase** letter
  - At least one **digit**
  - At least one **special character** (`@$!%*?&#`)
- Username validation added: only alphanumeric + dots/underscores/hyphens
- BCrypt strength 12 ensures brute-force is computationally expensive even if hashes leak

**Implementation Reference:**
- `SignUpRequest.java` → `@Pattern` annotation on password field

---

### THREAT 10: Server-Side JWT Secret Compromise

**Severity:** CRITICAL  
**Status:** ⚠️ RISK (not fixed — requires infrastructure)

**Attack Method:**  
If an attacker gains access to the server (via RCE, file disclosure, or repository access), they can read the JWT signing secret from `application.properties`. With the secret, they can:
1. Forge any JWT with any claims (including `dpop_jkt` matching their own key)
2. Bypass all authentication entirely
3. Impersonate any user including admins

**Current Vulnerability:**
```properties
# application.properties — SECRET IS IN PLAINTEXT
app.security.jwt.secret=c2VjdXJlYXBwLWp3dC1zZWNyZXQta2V5LWZvci1obWFjLXNoYTUxMi1...
```

**Why This Is Not Fixed in the POC:**
Secret management requires infrastructure (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or Kubernetes Secrets). This is outside the scope of a standalone Spring Boot POC.

**Recommendations for Production:**
1. Store JWT secret in **environment variables** (not in source code/properties)
2. Use **HashiCorp Vault** or cloud-native secret managers
3. Rotate the secret periodically (requires coordinated JWT invalidation)
4. Use **asymmetric signing (RS256)** instead of HMAC — the private key stays on the server, public key can be distributed for verification
5. Never commit secrets to version control

---

### THREAT 11: DPoP Replay in Multi-Instance Deployment

**Severity:** MEDIUM  
**Status:** ⚠️ RISK (not fixed — requires infrastructure)

**Attack Method:**  
In a multi-instance deployment behind a load balancer, each instance has its own Caffeine jti cache. An attacker could replay a DPoP proof to a different instance that hasn't seen the jti yet.

**Current Vulnerability:**
```java
// DPoPReplayProtectionService.java — IN-MEMORY ONLY
this.jtiCache = Caffeine.newBuilder()
    .maximumSize(100_000)
    .expireAfterWrite(Duration.ofSeconds(300))
    .build();
```

**Recommendations for Production:**
1. Replace Caffeine with **Redis** using `SETNX` with TTL matching proof age (300s)
2. Or use a shared database table with automatic TTL cleanup
3. The `DPoPReplayProtectionService` API (`isJtiUnique()`) is designed to be a drop-in replacement

---

### THREAT 12: JWT Non-Revocability (Post-Logout Abuse)

**Severity:** MEDIUM  
**Status:** ⚠️ RISK (not fixed — requires infrastructure)

**Attack Method:**  
After logout, the server clears the cookie (max-age=0). But if the attacker already intercepted the JWT before logout, the token remains valid until its natural expiry (15 minutes). The server has no mechanism to revoke individual tokens.

**Current Vulnerability:**
```java
// AuthController.logout() — only clears the cookie, doesn't invalidate the token
ResponseCookie clearCookie = ResponseCookie.from(JWT_COOKIE_NAME, "")
    .maxAge(0).build();
```

**Why DPoP Partially Mitigates This:**
Even with the stolen JWT, the attacker needs the client's DPoP private key. After logout, the client should destroy the private key, making the token useless even if intercepted.

**Recommendations for Production:**
1. Implement a **token blacklist** (Redis set with TTL = token remaining lifetime)
2. On logout, add the JWT's `jti` (if present) or token hash to the blacklist
3. `JwtAuthenticationFilter` checks the blacklist before accepting a token
4. Short token expiry (15 min) already limits the attack window

---

### THREAT 13: Phishing / Social Engineering

**Severity:** HIGH  
**Status:** ⚠️ RISK (not fixed — requires additional feature)

**Attack Method:**  
Attacker creates a fake login page that looks identical to the real application. The user enters their credentials on the fake site. The attacker now has valid username/password and can login legitimately with their own DPoP key pair.

**Why DPoP Does NOT Help:**
DPoP prevents **token theft**, not **credential theft**. The attacker performs a legitimate login with stolen credentials and binds their own key pair.

**Recommendations for Production:**
1. Implement **Multi-Factor Authentication (MFA)** — TOTP (Google Authenticator) or WebAuthn/FIDO2
2. WebAuthn is **phishing-resistant** because the browser verifies the origin (domain)
3. Add login notifications (email/SMS alerts on new device login)
4. Implement device fingerprinting for anomaly detection

---

### THREAT 14: Information Leakage via Error Messages

**Severity:** LOW  
**Status:** ✅ FIXED

**Attack Method:**  
Attacker triggers errors to extract internal details — stack traces, class names, database structure, library versions.

**Previous Vulnerability:**
```properties
spring.web.error.include-message=always
spring.web.error.include-stacktrace=on_param  # ?trace=true exposes full stack
```

**Fix Implemented:**
```properties
spring.web.error.include-message=never
spring.web.error.include-stacktrace=never
```

**Implementation Reference:**
- `application.properties` → `include-message=never`, `include-stacktrace=never`
- `GlobalExceptionHandler.java` → Returns generic "Internal server error" for unhandled exceptions

---

### THREAT 15: Database Credential Exposure

**Severity:** HIGH  
**Status:** ⚠️ RISK (not fixed — requires infrastructure)

**Attack Method:**  
Database credentials are in plaintext in `application.properties`:
```properties
spring.datasource.username=postgres
spring.datasource.password=postgres
```

**Recommendations for Production:**
1. Use environment variables: `${DB_USERNAME}`, `${DB_PASSWORD}`
2. Use Spring Cloud Vault or AWS Secrets Manager integration
3. Use connection pooling with IAM authentication (AWS RDS)
4. Restrict database user permissions (least privilege)

---

## Summary — Fixes Implemented

| # | Vulnerability | Fix | File Changed |
|---|--------------|-----|--------------|
| 1 | Account enumeration via different error messages | Generic "Invalid credentials" for all login failures | `AuthService.java` |
| 2 | Weak password allowed | Added regex pattern: uppercase + lowercase + digit + special char | `SignUpRequest.java` |
| 3 | Stack trace leakage via `?trace=true` | Set `include-stacktrace=never` and `include-message=never` | `application.properties` |
| 4 | Password hash info in debug logs | Removed hash prefix logging from login debug output | `AuthService.java` |
| 5 | Username allows special characters | Added pattern validation: alphanumeric + dots/underscores/hyphens | `SignUpRequest.java` |

---

## Remaining Risks — Requires Infrastructure / Separate Features

| # | Risk | Required Solution | Priority |
|---|------|-------------------|----------|
| 1 | JWT secret in plaintext | Environment variables / Secret manager (Vault) | **CRITICAL** |
| 2 | Database password in plaintext | Environment variables / Secret manager | **HIGH** |
| 3 | No rate limiting / brute-force protection | API-level rate limiting (per-IP, per-username, global) | **HIGH** |
| 4 | No MFA | Implement TOTP or WebAuthn/FIDO2 | **HIGH** |
| 5 | No JWT revocation / token blacklist | Redis-backed blacklist checked on every request | **MEDIUM** |
| 6 | DPoP jti cache per-instance only | Redis-backed shared jti store | **MEDIUM** |
| 7 | No login anomaly detection | Device fingerprinting + geolocation analysis | **LOW** |
| 8 | No audit logging | Structured audit log for all auth events | **LOW** |
| 9 | No JWT key rotation | Automated key rotation with grace period | **LOW** |

---

## Security Layers — Final Assessment

```
┌────────────────────────────────────────────────────────────────────┐
│                     SECURITY DEFENSE LAYERS                        │
├──────────────────────┬──────────┬──────────────────────────────────┤
│ Layer                │ Status   │ Protection                       │
├──────────────────────┼──────────┼──────────────────────────────────┤
│ HTTPS / TLS          │ ✅       │ Encrypted transport              │
│ HSTS                 │ ✅       │ Forces HTTPS for 1 year          │
│ HttpOnly Cookie      │ ✅       │ Token inaccessible to JavaScript │
│ Secure Cookie        │ ✅       │ Token only over HTTPS            │
│ SameSite=Strict      │ ✅       │ No cross-site cookie attachment  │
│ CSRF Token           │ ✅       │ Anti-forgery for POST/PUT/DELETE │
│ DPoP Binding         │ ✅       │ Token useless without priv key   │
│ DPoP Replay Cache    │ ✅       │ jti uniqueness enforcement       │
│ JWT HMAC-SHA512      │ ✅       │ Tamper-proof token               │
│ JWT 15-min Expiry    │ ✅       │ Short attack window              │
│ BCrypt-12            │ ✅       │ Expensive brute-force            │
│ Password Complexity  │ ✅       │ Upper+lower+digit+special        │
│ Account Enumeration  │ ✅       │ Generic error messages           │
│ CSP Headers          │ ✅       │ Block inline/external scripts    │
│ X-Frame-Options      │ ✅       │ Anti-clickjacking                │
│ RBAC (4 layers)      │ ✅       │ URL + JWT + Interceptor + Method │
│ Input Validation     │ ✅       │ Jakarta Bean Validation + JPA    │
│ Error Sanitisation   │ ✅       │ No stack traces / internal info  │
├──────────────────────┼──────────┼──────────────────────────────────┤
│ Rate Limiting        │ ❌       │ NOT implemented                  │
│ MFA                  │ ❌       │ NOT implemented                  │
│ Secret Management    │ ❌       │ Plaintext in properties          │
│ Token Blacklist      │ ❌       │ NOT implemented                  │
│ Distributed jti      │ ❌       │ In-memory only                   │
└──────────────────────┴──────────┴──────────────────────────────────┘
```

---

## Conclusion

The SecureApp POC implements **18 active security layers** covering transport, authentication, authorization, token protection, and input validation. The combination of **JWT + HttpOnly cookie + DPoP + CSRF + CSP** provides enterprise-grade security for a POC application.

**Key strength:** Even if the JWT cookie is intercepted (via network attack, cookie leak, or CSRF