# Security Implementation Report — SecureApp POC

**Date:** March 17, 2026  
**Project:** Agristack Secure Application — Java Springboot Backend (POC)  
**Version:** 2.0.0 (Stateless JWT + HttpOnly Cookie)  
**Proof of concept by Hardik Siroya.**

---

## Executive Summary

The SecureApp project is a Spring Boot 4.0.3 (Java 21) backend application built as a proof-of-concept to demonstrate enterprise-grade security practices. This version uses **stateless JWT-based authentication** — no server-side sessions are maintained. This document catalogues every security threat that has been identified and mitigated through our implementation, detailing the vulnerability, the standard solution, and how our project specifically resolves it.

---

## 1. Stolen Token Replay Attack (Token Hijacking)

**Security Issue:**  
If an attacker steals a user's JWT access token (e.g., via network sniffing, XSS, or malware), they can impersonate the user by replaying that token to the server. Standard JWT-based authentication alone cannot distinguish the legitimate user from an attacker who possesses the token.

**Solution:**  
DPoP (Demonstration of Proof-of-Possession) — as defined in RFC 9449 — binds a cryptographic keypair to the JWT token. Every request must include a freshly signed DPoP proof JWT. Even if the JWT token is stolen, the attacker cannot produce a valid proof without the client's private key.

**How Our Project Resolves It:**  
- At login, the client generates an ECDSA P-256 keypair locally (via the browser's WebCrypto API) and sends a self-signed DPoP proof JWT containing the public key in its header.  
- `DPoPSessionBindingService.validateAndGetThumbprint()` validates the proof and returns the JWK thumbprint.  
- The thumbprint is embedded in the JWT access token as the `dpop_jkt` claim (RFC 9449 §6).  
- For every subsequent request, `DPoPAuthenticationFilter` extracts the `DPoP` header, validates the JWT signature, verifies the `htm` (HTTP method) and `htu` (HTTP URI) claims, and confirms that the proof's JWK thumbprint matches the token-bound thumbprint from the `dpop_jkt` claim.  
- If the thumbprint does not match or the proof is missing, the request is rejected with HTTP 401.  
- **Result:** A stolen JWT token is useless without the client's private key.

---

## 2. DPoP Proof Replay Attack

**Security Issue:**  
An attacker who intercepts a valid DPoP proof JWT could replay it to gain unauthorized access, even though the proof itself is cryptographically valid.

**Solution:**  
Each DPoP proof must contain a unique `jti` (JWT ID) claim. The server must track previously seen `jti` values and reject duplicates within a time window.

**How Our Project Resolves It:**  
- `DPoPProofValidator` validates that every proof contains a non-blank `jti` claim.  
- `DPoPReplayProtectionService` maintains a high-performance Caffeine cache (up to 100,000 entries, TTL of 300 seconds) that records every accepted `jti`.  
- `DPoPAuthenticationFilter` calls `replayProtectionService.isJtiUnique(jti)` — if the `jti` has been seen before, the request is immediately rejected with "DPoP proof replay detected".  
- The `iat` (issued-at) claim is validated to be within a ±300-second window, ensuring stale proofs are rejected even if their `jti` is not cached.  
- **Result:** Captured DPoP proofs cannot be replayed.

---

## 3. JWT Token Expiration & Revocation

**Security Issue:**  
JWT tokens that never expire or have excessively long lifetimes give attackers a wide window to exploit stolen tokens. In stateless architectures, server-side revocation requires additional mechanisms.

**Solution:**  
Set short JWT expiration times. Combined with DPoP, even if a token is intercepted, the attacker cannot use it without the private key.

**How Our Project Resolves It:**  
- JWT tokens expire after **15 minutes** (`app.security.jwt.expiration-ms=900000`).  
- `JwtTokenService.validateAndGetClaims()` verifies the `exp` claim on every request — expired tokens are immediately rejected.  
- DPoP provides an additional layer: even within the 15-minute window, the token is useless without the client's private key.  
- For immediate revocation, a token blacklist/revocation list can be added (e.g., Redis-backed).  
- **Result:** Short-lived tokens minimize the attack window, and DPoP renders stolen tokens unusable.

---

## 4. Cross-Site Request Forgery (CSRF)

**Security Issue:**  
A malicious website can trick a user's browser into sending authenticated requests to our application, exploiting the browser's automatic cookie attachment.

**Solution:**  
Since the JWT is transported in an HttpOnly cookie (auto-attached by the browser), CSRF protection is required. Implement CSRF token protection so that every state-changing request must include a server-generated, unpredictable token.

**How Our Project Resolves It:**  
- `SecurityConfig` enables CSRF protection using `CookieCsrfTokenRepository.withHttpOnlyFalse()`, which provides the CSRF token to the frontend as a cookie (`XSRF-TOKEN`) readable by JavaScript (Angular's `HttpClient` automatically reads and sends it as `X-XSRF-TOKEN` header).  
- Public endpoints (`/auth/login`, `/auth/register`, `/auth/logout`, `/health`) are excluded from CSRF enforcement.  
- The DPoP header provides an additional layer — even if a CSRF attack bypasses the token, the attacker cannot produce a valid DPoP proof without the client's private key.  
- **Result:** State-changing requests from foreign origins are blocked by both CSRF tokens and DPoP proof requirements.

---

## 5. Cross-Site Scripting (XSS)

**Security Issue:**  
An attacker injects malicious JavaScript into the application (reflected, stored, or DOM-based XSS), which can steal tokens, or perform actions on behalf of the user.

**Solution:**  
Apply Content Security Policy (CSP) headers to restrict which scripts, styles, and resources the browser is allowed to load, and set additional XSS-protective headers.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` sets a strict **Content-Security-Policy** header: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` — this prevents loading scripts, fonts, or connections from external domains.  
- `SecurityConfig` also applies CSP via Spring Security's `.contentSecurityPolicy()`.  
- The **X-XSS-Protection** header (`1; mode=block`) is set for legacy browser protection.  
- The **X-Content-Type-Options** header (`nosniff`) prevents MIME-type sniffing that could lead to script execution.  
- JWT tokens are stored in an **HttpOnly cookie** — completely inaccessible to JavaScript, even if XSS is achieved. This is the most secure token storage mechanism available in browsers.  
- **Result:** Multiple layers prevent and mitigate XSS attacks. Even successful XSS cannot steal the JWT token.

---

## 6. Clickjacking

**Security Issue:**  
An attacker embeds the application inside an invisible `<iframe>` on a malicious site, tricking the user into clicking on hidden UI elements and performing unintended actions.

**Solution:**  
Set the `X-Frame-Options` header to `DENY` and use CSP's `frame-ancestors 'none'` directive to prevent the page from being rendered in any frame.

**How Our Project Resolves It:**  
- `SecurityConfig` configures `.frameOptions(frame -> frame.deny())`.  
- `SecurityHeadersFilter` additionally sets `X-Frame-Options: DENY` and includes `frame-ancestors 'none'` in the CSP header.  
- **Result:** The application cannot be embedded in any iframe, eliminating clickjacking.

---

## 7. Cross-Origin Resource Sharing (CORS) Misconfiguration

**Security Issue:**  
An overly permissive CORS policy (e.g., `Access-Control-Allow-Origin: *`) allows any website to make API calls to our backend using the user's credentials, enabling data theft.

**Solution:**  
Restrict CORS to only trusted origins, specific HTTP methods, and require credentials explicitly.

**How Our Project Resolves It:**  
- `SecurityConfig.corsConfigurationSource()` restricts allowed origins to `http://localhost:4200` only (the Angular frontend).  
- Allowed methods are explicitly listed: `GET, POST, PUT, DELETE, OPTIONS, PATCH`.  
- `allowCredentials` is set to `true` (required for Authorization headers).  
- Preflight cache max-age is set to 3600 seconds to reduce preflight overhead.  
- **Result:** Only the designated frontend origin can interact with the API.

---

## 8. Brute-Force Password Attacks / Weak Password Storage

**Security Issue:**  
If passwords are stored in plaintext, MD5, or SHA-1, attackers who gain database access can easily recover them. Additionally, weak hashing allows brute-force attacks.

**Solution:**  
Use a strong adaptive hashing algorithm (BCrypt, Argon2, or scrypt) with a sufficiently high work factor.

**How Our Project Resolves It:**  
- `SecurityConfig` configures `BCryptPasswordEncoder` with a strength of **12** (4,096 iterations), making brute-force attacks computationally expensive.  
- All passwords are hashed on registration (`passwordEncoder.encode()` in `AuthService.register()`).  
- Password verification uses `passwordEncoder.matches()`, which is timing-safe.  
- Pre-seeded user passwords in `init-database.sql` are also BCrypt-12 encoded.  
- **Result:** Even with database access, passwords cannot be feasibly reversed.

---

## 9. Man-in-the-Middle (MITM) Attack

**Security Issue:**  
Without HTTPS enforcement, all communications (including credentials and JWT tokens) can be intercepted by attackers on the network.

**Solution:**  
Enforce HTTPS via HTTP Strict Transport Security (HSTS).

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` sets `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` — once a browser visits the site over HTTPS, it will refuse to connect over HTTP for 1 year.  
- `SecurityUtil.isSecureConnection()` detects secure connections even behind reverse proxies (checking `X-Forwarded-Proto` and `X-SSL` headers).  
- JWT tokens are transmitted via the `Authorization` header which is protected by TLS in transit.  
- **Result:** Transport-layer security is enforced at the HTTP header level.

---

## 10. Unauthorized Access / Broken Access Control

**Security Issue:**  
Without proper authorization checks, any authenticated user could access admin-only endpoints or perform privileged actions.

**Solution:**  
Implement Role-Based Access Control (RBAC) with both declarative (annotation-based) and programmatic authorization.

**How Our Project Resolves It:**  
- **Declarative Authorization:** `@EnableMethodSecurity` enables `@PreAuthorize`, `@Secured`, and `@RolesAllowed` annotations. Controllers use `@PreAuthorize("hasRole('ADMIN')")` for admin endpoints and `@PreAuthorize("isAuthenticated()")` for general protected endpoints.  
- **Interceptor-Based Authorization:** `AuthorizationInterceptor` (registered via `WebMvcConfig`) acts as a second layer. It uses `RolePermissionMapping` — a centralized path-to-role mapping (e.g., `/admin/**` → `ROLE_ADMIN` only) — to enforce access control on every request. Every decision is logged with the format: `User | Role | Endpoint | Result`.  
- **URL-Level Authorization:** `SecurityConfig` uses `.authorizeHttpRequests()` to permit public endpoints and require authentication for all others.  
- **JWT Claims:** User roles are embedded in the JWT token and extracted by `JwtAuthenticationFilter` to populate the SecurityContext.  
- **Result:** Four-layered authorization (URL, JWT filter, interceptor, method) ensures defense in depth.

---

## 11. MIME-Type Sniffing Attack

**Security Issue:**  
Browsers may guess (sniff) the MIME type of a response, potentially executing a non-script response as JavaScript — leading to XSS.

**Solution:**  
Set the `X-Content-Type-Options: nosniff` header to prevent MIME-type sniffing.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` explicitly sets `X-Content-Type-Options: nosniff` on every response.  
- **Result:** Browsers strictly respect the declared `Content-Type`, preventing MIME-confusion attacks.

---

## 12. Information Leakage via Referrer Header

**Security Issue:**  
The browser's `Referer` header can leak sensitive URLs (containing tokens or internal paths) to third-party sites when following links.

**Solution:**  
Set a `Referrer-Policy` header to control what referrer information is sent.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` sets `Referrer-Policy: strict-origin-when-cross-origin` — full URL is only sent for same-origin requests; only the origin (no path) is sent for cross-origin HTTPS requests; nothing is sent for HTTPS→HTTP downgrades.  
- **Result:** Internal URL paths are never leaked to external sites.

---

## 13. Browser Feature Abuse (Camera, Microphone, Geolocation, etc.)

**Security Issue:**  
If an attacker injects code into the application (via XSS or a compromised dependency), they could exploit browser APIs to access the camera, microphone, geolocation, payment info, or USB devices.

**Solution:**  
Set a `Permissions-Policy` header to explicitly disable unnecessary browser features.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` sets `Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()` — all sensitive browser features are disabled.  
- **Result:** Even if malicious code is injected, it cannot access device hardware or payment APIs.

---

## 14. Sensitive Data Caching

**Security Issue:**  
Browsers and intermediate proxies may cache API responses containing sensitive data (user info, token details). An attacker with access to the browser or cache can retrieve this data.

**Solution:**  
Set cache-control headers to prevent caching of sensitive responses.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` sets `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, `Pragma: no-cache`, and `Expires: 0` on every response.  
- **Result:** No sensitive API response is cached by browsers or proxies.

---

## 15. Input Validation & Injection Attacks

**Security Issue:**  
Unvalidated user input can lead to SQL injection, script injection, or application logic bypass. Missing validation allows malformed data to corrupt the system.

**Solution:**  
Apply strict server-side validation on all inputs using Jakarta Bean Validation and parameterized queries.

**How Our Project Resolves It:**  
- DTOs use Jakarta Validation annotations: `@NotBlank`, `@Email`, `@Size` (e.g., `LoginRequest`, `SignUpRequest`).  
- Controllers use `@Valid` on `@RequestBody` parameters, triggering automatic validation before the method executes.  
- `GlobalExceptionHandler` catches `MethodArgumentNotValidException` and returns structured error responses without leaking internal details.  
- JPA/Hibernate uses parameterized queries by default, preventing SQL injection.  
- Entity-level validation (`@NotBlank`, `@Email`, `@Column(length=...)`) provides a second validation layer at the persistence level.  
- **Result:** Malformed or malicious inputs are rejected at multiple layers.

---

## 16. Error Information Disclosure

**Security Issue:**  
Detailed error messages, stack traces, or internal system information exposed to end users can help attackers understand the application's internals and find further vulnerabilities.

**Solution:**  
Use a global exception handler that returns generic, safe error messages and hide technical details.

**How Our Project Resolves It:**  
- `GlobalExceptionHandler` catches all exceptions (`@RestControllerAdvice`) and returns a standardized `ApiResponse` with generic messages (e.g., "Internal server error" for unhandled exceptions).  
- `application.properties` sets `spring.web.error.include-exception=false` to suppress exception class names in error responses.  
- Stack traces are controlled via `include-stacktrace=on_param` (only included if explicitly requested via query parameter — disabled by default).  
- All security filters (`JwtAuthenticationFilter`, `DPoPAuthenticationFilter`, `AuthorizationInterceptor`) return consistent JSON error responses without exposing internal state.  
- **Result:** Attackers cannot extract system internals from error responses.

---

## 17. Stateless Scalability (No Session State)

**Security Issue:**  
Storing sessions in application memory or a shared database creates scaling bottlenecks, single points of failure, and requires session affinity or distributed session stores.

**Solution:**  
Use stateless JWT-based authentication where all authentication state is carried in the token itself.

**How Our Project Resolves It:**  
- `SecurityConfig` sets `SessionCreationPolicy.STATELESS` — Spring Security never creates or uses HTTP sessions.  
- JWT tokens contain all necessary claims: `sub` (username), `roles`, `userId`, `dpop_jkt` (DPoP binding).  
- No session tables, no session cookies, no session replication needed.  
- Any application instance can validate any token — enabling horizontal scaling behind a load balancer without sticky sessions.  
- **Result:** The application is fully stateless and horizontally scalable.

---

## 18. JWT Token Tampering

**Security Issue:**  
An attacker could modify JWT token claims (e.g., change roles from USER to ADMIN) to escalate privileges.

**Solution:**  
Sign JWT tokens with a strong cryptographic key. The server verifies the signature on every request, detecting any tampering.

**How Our Project Resolves It:**  
- `JwtTokenService` signs tokens with HMAC-SHA512 (`Jwts.SIG.HS512`) using a 512-bit secret key.  
- `JwtAuthenticationFilter` verifies the token signature on every request via `jwtTokenService.validateAndGetClaims()`.  
- Any modification to the token payload invalidates the signature, causing immediate rejection.  
- The issuer claim (`iss`) is also validated to prevent tokens from other systems.  
- **Result:** Token tampering is cryptographically impossible without the secret key.

---

## 19. Privilege Escalation via Missing Method-Level Security

**Security Issue:**  
Even if URL-level authorization is configured, an attacker could potentially bypass it if individual controller methods don't enforce their own authorization checks.

**Solution:**  
Enable method-level security annotations for fine-grained access control directly on business logic.

**How Our Project Resolves It:**  
- `@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)` enables three annotation styles.  
- `DashboardController` uses `@PreAuthorize("hasRole('ADMIN')")` on admin-only endpoints and `@PreAuthorize("isAuthenticated()")` on user endpoints.  
- `AuthorizationInterceptor` provides an additional programmatic layer with centralized role-permission mapping and audit logging.  
- **Result:** Authorization is enforced at the method level, independent of URL configuration.

---

## 20. Account Enumeration

**Security Issue:**  
Different error messages for "username not found" vs. "wrong password" allow attackers to enumerate valid usernames.

**Solution:**  
Use generic error messages that do not reveal whether the username or password was incorrect.

**How Our Project Resolves It:**  
- `AuthService.login()` throws `BadRequestException("Invalid credentials")` for wrong passwords — a generic message that does not distinguish between wrong username and wrong password.  
- Account status checks (disabled, locked) return similarly generic messages.  
- **Result:** Attackers cannot determine whether a username exists in the system via login error messages.

---

## 21. Form Action / Base URI Hijacking

**Security Issue:**  
If an attacker can inject HTML, they could change the `<base>` tag or `<form action>` to redirect form submissions (including credentials) to an attacker-controlled server.

**Solution:**  
Use CSP directives `base-uri 'self'` and `form-action 'self'` to restrict these elements.

**How Our Project Resolves It:**  
- `SecurityHeadersFilter` includes `base-uri 'self'` and `form-action 'self'` in the Content-Security-Policy header.  
- **Result:** Even if HTML injection occurs, forms and base URIs cannot point to external domains.

---

## Summary Table

| # | Security Issue | Solution | Implementation Component |
|---|---------------|----------|--------------------------|
| 1 | Token Hijacking | DPoP (RFC 9449) Proof-of-Possession | `DPoPAuthenticationFilter`, `DPoPSessionBindingService`, `DPoPProofValidator` |
| 2 | DPoP Proof Replay | JTI uniqueness cache + timestamp validation | `DPoPReplayProtectionService`, `DPoPProofValidator` |
| 3 | Token Expiration | Short-lived JWT (15 min) + DPoP binding | `JwtTokenService`, `JwtAuthenticationFilter` |
| 4 | CSRF | CookieCsrfTokenRepository + DPoP | `SecurityConfig` (CookieCsrfTokenRepository), DPoP |
| 5 | XSS | CSP, X-XSS-Protection, HttpOnly cookie | `SecurityHeadersFilter`, `SecurityConfig`, HttpOnly cookie |
| 6 | Clickjacking | X-Frame-Options DENY + frame-ancestors | `SecurityConfig`, `SecurityHeadersFilter` |
| 7 | CORS Misconfiguration | Strict origin whitelist | `SecurityConfig.corsConfigurationSource()` |
| 8 | Weak Password Storage | BCrypt strength 12 | `SecurityConfig`, `AuthService` |
| 9 | Man-in-the-Middle | HSTS | `SecurityHeadersFilter` |
| 10 | Broken Access Control | 4-layer RBAC (URL, JWT, Interceptor, Method) | `SecurityConfig`, `JwtAuthenticationFilter`, `AuthorizationInterceptor`, `@PreAuthorize` |
| 11 | MIME Sniffing | X-Content-Type-Options: nosniff | `SecurityHeadersFilter` |
| 12 | Referrer Leakage | Referrer-Policy | `SecurityHeadersFilter` |
| 13 | Browser Feature Abuse | Permissions-Policy | `SecurityHeadersFilter` |
| 14 | Sensitive Data Caching | Cache-Control: no-store | `SecurityHeadersFilter` |
| 15 | Input Injection | Jakarta Validation + Parameterized Queries | DTOs, `@Valid`, JPA/Hibernate |
| 16 | Error Information Disclosure | Global exception handler | `GlobalExceptionHandler`, `application.properties` |
| 17 | Stateless Scalability | JWT tokens, no sessions | `SecurityConfig` (STATELESS), `JwtTokenService` |
| 18 | JWT Token Tampering | HMAC-SHA512 signature verification | `JwtTokenService`, `JwtAuthenticationFilter` |
| 19 | Privilege Escalation | Method-level security annotations | `@EnableMethodSecurity`, `@PreAuthorize` |
| 20 | Account Enumeration | Generic error messages | `AuthService` |
| 21 | Form/Base URI Hijacking | CSP base-uri + form-action | `SecurityHeadersFilter` |

---

## Conclusion

This POC demonstrates a **defense-in-depth** approach where no single mechanism is relied upon for security. The combination of **stateless JWT authentication**, DPoP proof-of-possession, comprehensive security headers, RBAC, input validation, and centralized error handling creates multiple overlapping layers of protection. Each layer is designed so that even if one is bypassed, the others continue to protect the application.

The stateless architecture eliminates the need for server-side session management, enabling **horizontal scaling** without session affinity or distributed session stores. JWT tokens carry all necessary authentication state, while DPoP ensures that stolen tokens are useless without the client's private key.

The architecture is production-ready and can be extended with additional measures such as rate limiting, IP-based throttling, Redis-backed token revocation, and refresh token rotation.
