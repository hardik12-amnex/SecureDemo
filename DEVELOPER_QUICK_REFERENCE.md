# Spring Security Quick Reference Guide

## For Developers

### 1. Protecting Methods with Authorization

#### Using @PreAuthorize (SpEL Expression)
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long userId) {
    // Only ADMIN users can call this
}

@PreAuthorize("@userService.isOwner(#userId, authentication.principal.username)")
public User updateUser(Long userId, User user) {
    // Check if user owns the resource
}
```

#### Using @Secured (Role Check)
```java
@Secured("ROLE_USER")
public List<Dashboard> getUserDashboards() {
    // Users with ROLE_USER can call this
}
```

#### Using @RolesAllowed (JSR-250)
```java
@RolesAllowed("ROLE_MANAGER")
public void approveRequest(Long requestId) {
    // Only MANAGER role can access
}
```

### 2. Getting Current User Information

```java
@GetMapping("/profile")
public User getCurrentUserProfile() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String username = auth.getName();
    Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
    return userService.findByUsername(username);
}
```

### 3. Checking User Roles in Code

```java
@Service
public class DashboardService {
    
    public List<Dashboard> getDashboards() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
            .anyMatch(ga -> ga.getAuthority().equals("ROLE_ADMIN"));
        
        if (isAdmin) {
            return dashboardRepository.findAll(); // All dashboards
        } else {
            return dashboardRepository.findByOwner(auth.getName()); // User's dashboards
        }
    }
}
```

### 4. CSRF Token in Frontend (Angular Example)

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';

@Injectable()
export class ApiService {
    
    constructor(private http: HttpClient) {}
    
    // Get CSRF token from cookie
    private getCsrfToken(): string {
        const token = this.getCookie('X-CSRF-TOKEN');
        return token || '';
    }
    
    private getCookie(name: string): string {
        let cookieValue = '';
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (const cookie of cookies) {
                const c = cookie.trim();
                if (c.indexOf(name + '=') === 0) {
                    cookieValue = c.substring(name.length + 1);
                    break;
                }
            }
        }
        return cookieValue;
    }
    
    // Make POST request with CSRF token
    post<T>(url: string, data: any): Observable<T> {
        const headers = new HttpHeaders({
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': this.getCsrfToken()
        });
        return this.http.post<T>(url, data, { headers, withCredentials: true });
    }
}
```

### 5. Login Request Format

**Endpoint**: `POST /api/auth/login`

**Request Body**:
```json
{
    "username": "john@example.com",
    "password": "securePassword123"
}
```

**Response** (on success):
```json
{
    "message": "Login successful",
    "user": {
        "id": 1,
        "username": "john@example.com",
        "email": "john@example.com"
    }
}
```

**Cookies in Response**:
- `JSESSIONID`: Session ID (HttpOnly, Secure, SameSite=Strict)
- `X-CSRF-TOKEN`: CSRF protection token

### 6. Logout Request

**Endpoint**: `POST /api/auth/logout`

**Headers Required**:
```
X-CSRF-TOKEN: <token_value>
```

**Response** (on success):
```json
{
    "message": "Logout successful"
}
```

### 7. Sample Protected Endpoint

```java
@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {
    
    @Autowired
    private DashboardService dashboardService;
    
    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getDashboards() {
        List<Dashboard> dashboards = dashboardService.getDashboards();
        return ResponseEntity.ok(dashboards);
    }
    
    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> createDashboard(@RequestBody CreateDashboardRequest request) {
        Dashboard dashboard = dashboardService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(dashboard);
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("@dashboardService.isOwner(#id, authentication.principal.username)")
    public ResponseEntity<?> deleteDashboard(@PathVariable Long id) {
        dashboardService.delete(id);
        return ResponseEntity.ok(new ApiResponse("Dashboard deleted successfully"));
    }
}
```

### 8. Testing Authenticated Requests with cURL

```bash
# 1. Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password123"}' \
  -c cookies.txt

# 2. Extract CSRF token from response headers or body
# The token might be in Set-Cookie header as X-CSRF-TOKEN

# 3. Make authenticated request with CSRF token
curl -X GET http://localhost:8080/api/dashboard \
  -H "X-CSRF-TOKEN: <token_from_response>" \
  -b cookies.txt

# 4. Logout
curl -X POST http://localhost:8080/api/auth/logout \
  -H "X-CSRF-TOKEN: <token>" \
  -b cookies.txt
```

### 9. Testing Authenticated Requests with Postman

**Step 1: Login**
- Method: `POST`
- URL: `http://localhost:8080/api/auth/login`
- Body (JSON):
  ```json
  {
    "username": "user@example.com",
    "password": "password123"
  }
  ```

**Step 2: Get CSRF Token**
- In response Headers, find `Set-Cookie` with `X-CSRF-TOKEN`
- Copy the token value

**Step 3: Make Authenticated Request**
- Add header: `X-CSRF-TOKEN: <token_value>`
- Postman automatically manages cookies with `withCredentials: true`

**Step 4: Logout**
- Method: `POST`
- URL: `http://localhost:8080/api/auth/logout`
- Header: `X-CSRF-TOKEN: <token_value>`

### 10. Common Issues and Solutions

**Issue**: 401 Unauthorized on protected endpoint
```
Solution: 
1. Ensure you're logged in
2. Check JSESSIONID cookie is present
3. Verify session hasn't timed out (15 minutes)
```

**Issue**: 403 Forbidden on POST/PUT/DELETE
```
Solution:
1. Include X-CSRF-TOKEN header
2. Verify token value from cookie
3. Check token hasn't expired
```

**Issue**: CORS error from frontend
```
Solution:
1. Verify frontend URL is http://localhost:4200
2. Ensure withCredentials: true in AJAX requests
3. Check browser console for exact error
```

**Issue**: Session expires too quickly
```
Solution:
1. Adjust server.servlet.session.timeout in application.properties
2. Default is 15 minutes, increase if needed
3. Restart application after changes
```

### 11. Security Headers Verification

**Check security headers with curl**:
```bash
curl -i http://localhost:8080/api/protected
```

**Expected headers**:
```
Content-Security-Policy: default-src 'self'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: accelerometer=(), camera=(), ...
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

### 12. User Role Model

```java
@Entity
@Table(name = "roles")
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name; // Format: ROLE_ADMIN, ROLE_USER, ROLE_MANAGER
    
    private String description;
}
```

**Standard Role Names**:
- `ROLE_ADMIN` - Administrator with full access
- `ROLE_USER` - Regular user with limited access
- `ROLE_MODERATOR` - Moderator with content management rights

---

## Configuration Files Overview

### SecurityConfig.java
- Main security configuration
- Defines security filter chain
- Configures CSRF, CORS, headers
- Sets up authorization rules
- Registers SessionValidationFilter

### SessionConfig.java
- Configures JDBC-backed session storage (PostgreSQL)
- Sets session timeout (15 minutes / 900 seconds)
- Integrated with application.properties

### WebMvcConfig.java
- Registers AuthorizationInterceptor into MVC chain
- Excludes public endpoints from interception

### SecurityHeadersFilter.java
- Custom filter for additional security headers
- Applied to all requests
- Adds X-Content-Type-Options, HSTS, etc. (8 headers total)

### SessionValidationFilter.java
- Enterprise-grade session validation
- 4-step validation: session exists, not expired, auth context, username attribute
- Returns 401 JSON for invalid sessions
- Excludes public endpoints

### AuthorizationInterceptor.java
- MVC interceptor for role-based path authorization
- Uses RolePermissionMapping for centralized permission checks
- Logs every decision: User, Role, Endpoint, Result
- Returns 403 JSON for denied access

### RolePermissionMapping.java
- Centralized role-to-path permission map
- AntPathMatcher for flexible matching
- `/admin/**` -> ROLE_ADMIN only
- `/dashboard/**` -> ROLE_USER, ROLE_ADMIN

### SecurityUtils.java
- Thread-safe static utility class
- getCurrentUser(), getCurrentUserRoles(), hasRole()
- isAuthenticated(), session attribute helpers

### SecurityUtil.java
- Request-level utilities
- getClientIp() — extracts IP from X-Forwarded-For / X-Real-IP
- isSecureConnection() — detects HTTPS via proxy headers

### application.properties
- Session cookie configuration (HttpOnly, Secure, SameSite=Strict)
- Session timeout (15m) and JDBC store
- Database connection (PostgreSQL)
- CORS and security flags
- Logging levels

---

## Important Notes

⚠️ **Production Checklist**:
1. Enable HTTPS (Secure flag requires this)
2. Update CORS origins from localhost to actual domain
3. Configure database for production
4. Set strong session timeout
5. Monitor session storage
6. Enable security header preload
7. Test all authentication flows
8. Implement audit logging
9. Set up rate limiting for login attempts
10. Configure backup strategy for sessions

---

## Resources

- API Postman Collection: `SecureApp-API.postman_collection.json`
- Security Documentation: `SECURITY_IMPLEMENTATION.md`
- Implementation Summary: `IMPLEMENTATION_SUMMARY.md`
- Spring Security Docs: https://spring.io/projects/spring-security

