# Spring Security Implementation Guide

## Overview
This document describes the comprehensive Spring Security configuration implemented for the SecureApp project. The implementation uses session-based authentication with enterprise-grade security features.

## Architecture

### Security Components

#### 1. **SecurityConfig** (`config/SecurityConfig.java`)
Main Spring Security configuration class that enforces:
- Session-based authentication
- CSRF protection using CookieCsrfTokenRepository
- Method-level security with @EnableMethodSecurity
- CORS policy (localhost:4200 only)
- Security headers via HttpSecurity
- Authorization rules for endpoints

#### 2. **SessionConfig** (`config/SessionConfig.java`)
Configures database-backed session management:
- JDBC session store for distributed systems
- 15-minute session timeout (900 seconds)
- HttpOnly, Secure, and SameSite=Strict cookies
- Configured via application.properties

#### 3. **SessionValidationFilter** (`filter/SessionValidationFilter.java`)
Enterprise-grade custom filter for session validation:
- Validates session exists (does not create new ones)
- Validates session has not expired (defense-in-depth time check)
- Validates authenticated user in SecurityContext
- Validates session contains user attributes
- Returns 401 JSON response on failure
- Excludes public endpoints (/auth/login, /auth/register, /auth/logout, /health)

#### 4. **SecurityHeadersFilter** (`filter/SecurityHeadersFilter.java`)
Custom filter adding comprehensive security headers:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cache-Control headers

---

## Configuration Details

### Session Management

#### Session Timeout
- **Duration**: 15 minutes (900 seconds)
- **Configuration**: `server.servlet.session.timeout=15m` in application.properties
- **MaxInactiveInterval**: 900 seconds in @EnableJdbcHttpSession

#### Session Cookie Settings
```properties
server.servlet.session.cookie.name=JSESSIONID
server.servlet.session.cookie.path=/
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict
server.servlet.session.cookie.max-age=900
```

**Cookie Flags Explanation:**
- **HttpOnly**: Prevents JavaScript from accessing the session cookie, protecting against XSS attacks
- **Secure**: Cookie is only sent over HTTPS (must be enabled in production)
- **SameSite=Strict**: Cookie is never sent in cross-site requests, preventing CSRF attacks
- **Max-Age**: Cookie lifetime set to 900 seconds (15 minutes)

#### Session Storage
- **Store Type**: JDBC (database-backed)
- **Database**: PostgreSQL
- **Session Tables**: SPRING_SESSION, SPRING_SESSION_ATTRIBUTES (created by init-database.sql)
- **Benefits**: 
  - Distributed system support
  - Session persistence across restarts
  - Scalability across multiple instances
  - No additional infrastructure (uses existing PostgreSQL)

### CSRF Protection

#### Configuration
```java
.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
)
```

**How it works:**
1. CSRF token is generated and stored in a cookie
2. Token is sent with each state-changing request (POST, PUT, DELETE, PATCH)
3. Server validates the token before processing the request
4. `withHttpOnlyFalse()` allows JavaScript to read the token (necessary for AJAX requests)

### Method-Level Security

#### Enabled Annotations
```java
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
```

This enables three annotation styles:

**1. @PreAuthorize / @PostAuthorize (SpEL-based)**
```java
@PreAuthorize("hasRole('ADMIN')")
@PostAuthorize("returnObject.owner == authentication.principal.username")
public void adminAction() { }
```

**2. @Secured (Role-based)**
```java
@Secured("ROLE_ADMIN")
public void restrictedAction() { }
```

**3. @RolesAllowed (JSR-250 standard)**
```java
@RolesAllowed("ROLE_USER")
public void userAction() { }
```

### Authorization Rules

#### Public Endpoints
```java
.requestMatchers("/auth/login", "/auth/register").permitAll()
.requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
.requestMatchers("/api/health", "/actuator/health").permitAll()
```

#### Protected Endpoints
```java
.anyRequest().authenticated()
```

All other endpoints require authentication.

### CORS Configuration

#### Allowed Origins
- **http://localhost:4200** (Angular frontend)

#### Allowed Methods
- GET, POST, PUT, DELETE, OPTIONS, PATCH

#### Allowed Headers
- All headers are allowed

#### Exposed Headers
- Authorization
- Content-Type

#### Credentials
- Enabled to support cookie-based authentication

#### Configuration
```java
CorsConfiguration configuration = new CorsConfiguration();
configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
configuration.setAllowedHeaders(Arrays.asList("*"));
configuration.setAllowCredentials(true);
configuration.setMaxAge(3600L);
```

### Security Headers

#### Implemented Headers

**1. Content-Security-Policy (CSP)**
```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
base-uri 'self';
form-action 'self';
```

**Purpose**: Restricts the sources from which content can be loaded, preventing XSS attacks.

**2. X-Frame-Options: DENY**
Prevents clickjacking attacks by disallowing the page from being framed by any external site.

**3. X-Content-Type-Options: nosniff**
Prevents browsers from MIME-sniffing files, ensuring they're interpreted as declared type.

**4. Strict-Transport-Security (HSTS)**
```
max-age=31536000; includeSubDomains; preload
```
- Enforces HTTPS for 1 year (31,536,000 seconds)
- Applies to all subdomains
- Preload enabled for HSTS preload list inclusion

**5. X-XSS-Protection**
```
1; mode=block
```
Legacy header for older browsers, enables XSS filtering and blocking.

**6. Referrer-Policy: strict-origin-when-cross-origin**
Controls how much referrer information is sent with requests.

**7. Permissions-Policy**
Disables unnecessary browser features:
- Accelerometer, Camera, Geolocation, Gyroscope
- Magnetometer, Microphone, Payment, USB

**8. Cache-Control**
```
no-store, no-cache, must-revalidate, max-age=0
```
Prevents caching of sensitive data.

---

## Authentication Flow

### Login Process
1. User sends credentials to `/api/auth/login`
2. CustomUserDetailsService loads user from database
3. Password is verified using BCryptPasswordEncoder
4. Session is created and JSESSIONID cookie is issued
5. CSRF token is generated and sent to client
6. Client must include CSRF token in subsequent requests

### Subsequent Requests
1. Client sends request with JSESSIONID cookie
2. Client includes CSRF token in request headers (for state-changing operations)
3. Server validates session and CSRF token
4. Request is authorized based on user roles
5. Response is sent with security headers

### Logout Process
1. User sends request to `/api/auth/logout`
2. Session is invalidated
3. JSESSIONID cookie is deleted
4. Authentication is cleared
5. User is redirected to login page

---

## Password Encoding

### Configuration
```java
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
}
```

**BCrypt Strength: 12**
- Provides strong password hashing
- Includes automatic salt generation
- Resistant to rainbow table attacks
- Computational cost increases with strength level

---

## Development vs. Production Considerations

### Development
- Use `http://localhost:4200` for CORS
- Set `server.servlet.session.cookie.secure=true` (requires HTTPS setup)
- Session timeout: 15 minutes

### Production
- Update CORS origins to actual domain
- Enable HTTPS/TLS (Secure flag will be active)
- Consider increasing session timeout for desktop applications
- Monitor session storage database capacity
- Enable HSTS preload at https://hstspreload.org/
- Use environment-specific application.properties files

---

## Testing Security

### Test CSRF Protection
```bash
# Request without CSRF token should fail
curl -X POST http://localhost:8080/api/protected \
  -H "Content-Type: application/json" \
  --cookie "JSESSIONID=..."
# Response: 403 Forbidden
```

### Test CORS
```bash
# Invalid origin should be rejected
curl -X GET http://localhost:8080/api/protected \
  -H "Origin: http://localhost:3000"
# Response: CORS error
```

### Test Security Headers
```bash
# Check response headers
curl -i http://localhost:8080/api/protected

# Look for:
# Content-Security-Policy
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Strict-Transport-Security
# X-XSS-Protection
# Referrer-Policy
# Permissions-Policy
# Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

### Test Session Timeout
1. Login to the application
2. Wait 15 minutes
3. Attempt to make an authenticated request
4. Should receive 401 Unauthorized

---

## Security Best Practices Implemented

### 1. Defense in Depth
Multiple layers of security:
- Session validation
- CSRF protection
- CORS policy
- Security headers
- Method-level authorization
- Password encryption

### 2. Principle of Least Privilege
- Only necessary endpoints are public
- All other endpoints require authentication
- Role-based access control available
- Method-level security for fine-grained control

### 3. Secure by Default
- HttpOnly cookies prevent XSS access
- Secure flag requires HTTPS
- SameSite=Strict prevents CSRF in modern browsers
- CSRF token for additional protection

### 4. Security Headers
Comprehensive headers prevent:
- Clickjacking (X-Frame-Options)
- MIME-sniffing (X-Content-Type-Options)
- XSS attacks (CSP, X-XSS-Protection)
- Man-in-the-middle (HSTS)
- Unnecessary feature exposure (Permissions-Policy)

---

## Dependencies

Required Maven dependencies (already included in pom.xml):

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-jdbc</artifactId>
</dependency>
```

---

## Configuration Summary

| Setting | Value | Purpose |
|---------|-------|---------|
| Session Timeout | 15 minutes | Limits session validity |
| CSRF Protection | Enabled | Prevents CSRF attacks |
| CORS Origin | http://localhost:4200 | Only allows frontend access |
| Cookie HttpOnly | true | Prevents XSS cookie theft |
| Cookie Secure | true | HTTPS only transmission |
| Cookie SameSite | Strict | Cross-site protection |
| Method Security | Enabled | Fine-grained authorization |
| Password Encoder | BCrypt-12 | Strong password hashing |
| Session Store | JDBC | Distributed system support |

---

## Troubleshooting

### Issue: CORS Error
**Solution**: Ensure frontend origin matches CORS configuration and credentials are enabled.

### Issue: 403 Forbidden on POST/PUT/DELETE
**Solution**: Include CSRF token in request header. The token should be available in the response cookies.

### Issue: Session expires too quickly
**Solution**: Adjust `server.servlet.session.timeout` in application.properties.

### Issue: Secure cookie not working
**Solution**: Ensure HTTPS is enabled. In development, you can temporarily disable the Secure flag in application.properties.

---

## References

- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
- [CSRF Protection Guide](https://owasp.org/www-community/attacks/csrf)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

